// Package handlers provides HTTP request handlers for the Bifrost HTTP transport.
// This file holds the reusable virtual key rotation implementation shared by the
// rotate endpoints and background producers such as enterprise scheduled rotation.
package handlers

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"sync"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/configstore"
	configstoreTables "github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/maximhq/bifrost/plugins/governance"
	"gorm.io/gorm"
)

// VirtualKeyRotator rotates a virtual key's value exactly the way
// POST /api/governance/virtual-keys/{vk_id}/rotate does, so every producer
// (manual endpoint, bulk endpoint, scheduled enterprise rotation) shares one
// implementation of the cooldown / previous-value rules.
type VirtualKeyRotator struct {
	configStore       configstore.ConfigStore
	governanceManager GovernanceManager
}

// Fixed stripes bound coordinator memory to 2 KiB, shared by all rotation
// producers. Locks cover persistence and installation, never inference reads.
var rotationCoordinator [256]sync.Mutex

func rotationMutex(id string) *sync.Mutex {
	var hash uint32
	for i := 0; i < len(id); i++ {
		hash = hash*33 ^ uint32(id[i])
	}
	return &rotationCoordinator[hash%uint32(len(rotationCoordinator))]
}

// NewVirtualKeyRotator builds a rotator over the given store and governance
// manager. The manager is what reloads the rotated key into in-memory
// enforcement (and, in enterprise, gossips it to cluster peers).
func NewVirtualKeyRotator(configStore configstore.ConfigStore, governanceManager GovernanceManager) *VirtualKeyRotator {
	return &VirtualKeyRotator{configStore: configStore, governanceManager: governanceManager}
}

// VKRotationCooldown reads the effective rotation grace period from the stored
// client config. Errors degrade to 0 (immediate flip), never block a rotation.
func (r *VirtualKeyRotator) VKRotationCooldown(ctx context.Context) time.Duration {
	clientConfig, err := r.configStore.GetClientConfig(ctx)
	if err != nil || clientConfig == nil {
		return 0
	}
	return clientConfig.VKRotationCooldown.D()
}

// RotateVirtualKey generates a fresh value for the virtual key, applies the
// cooldown rules (the retired value stays valid until now+cooldown, or is
// dropped immediately when no cooldown is configured), persists the change,
// reloads in-memory governance and hydrates VK-scoped model-config governance
// onto the returned row. Callers passing a background context run unscoped by
// DAC, which is intended for system-initiated rotation.
func (r *VirtualKeyRotator) RotateVirtualKey(ctx context.Context, vkID string) (*configstoreTables.TableVirtualKey, error) {
	return r.rotateVirtualKey(ctx, vkID, false)
}

// RotateVirtualKeyImmediately is the explicit security rotation used by the
// management UI: the retired credential has no grace period.
func (r *VirtualKeyRotator) RotateVirtualKeyImmediately(ctx context.Context, vkID string) (*configstoreTables.TableVirtualKey, error) {
	return r.rotateVirtualKey(ctx, vkID, true)
}

func (r *VirtualKeyRotator) rotateVirtualKey(ctx context.Context, vkID string, immediate bool) (*configstoreTables.TableVirtualKey, error) {
	lock := rotationMutex(vkID)
	lock.Lock()
	defer lock.Unlock()
	vk, err := r.configStore.GetVirtualKey(ctx, vkID)
	if err != nil {
		return nil, err
	}
	oldValue := vk.Value.GetValue()
	retiredSecrets := struct{ Value, PreviousValue schemas.SecretVar }{vk.Value, vk.PreviousValue}
	expectedHash := vk.ValueHash
	vk.Value = *schemas.NewSecretVar(governance.GenerateVirtualKey())
	if vk.Value.GetValue() == oldValue {
		return nil, fmt.Errorf("generated virtual key matched existing value")
	}
	issuedValue := vk.Value.GetValue()
	// RotatedAt marks this update as a rotation, making the grace-period fields
	// authoritative in UpdateVirtualKey (a plain update carries them over
	// instead). With a cooldown the retired value keeps authenticating until
	// the expiry; repeated rotation overwrites the previous value, so only one
	// grace value exists at a time and the second-oldest dies immediately.
	now := time.Now().UTC()
	vk.RotatedAt = &now
	if cooldown := r.VKRotationCooldown(ctx); !immediate && cooldown > 0 {
		vk.PreviousValue = *schemas.NewSecretVar(oldValue)
		expiresAt := now.Add(cooldown)
		vk.PreviousValueExpiresAt = &expiresAt
	} else {
		vk.ClearPreviousValue()
	}
	// Vault writes are external to SQL transactions. Allocate immutable paths
	// so a losing CAS or rolled-back SQL write cannot overwrite a live secret.
	base := schemas.VaultBasePath(vk.TableName(), vk.ID)
	newPaths := []string{}
	committed := false
	defer func() {
		if !committed && len(newPaths) > 0 {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			for _, path := range newPaths {
				if err := schemas.VaultRemoveHook(cleanup, path); err != nil {
					logger.Warn("failed to clean up an uncommitted virtual-key Vault issuance")
				}
			}
		}
	}()
	if schemas.VaultStoreWriteEnabled() {
		issuanceBase := base + "/rotations/" + uuid.NewString()
		for _, entry := range []struct {
			field *schemas.SecretVar
			name  string
		}{{&vk.Value, "value"}, {&vk.PreviousValue, "previous_value"}} {
			if !entry.field.IsSet() {
				continue
			}
			plain := entry.field.GetValue()
			path := issuanceBase + "/" + entry.name
			newPaths = append(newPaths, path)
			if err := schemas.StoreVaultSecretVar(ctx, path, entry.field); err != nil {
				return nil, fmt.Errorf("failed to store virtual-key issuance")
			}
			entry.field.Val = plain // BeforeSave hashes plaintext; Value persists the ref.
		}
	}
	// MCP OAuth grants minted in vk mode are bound to this key's row id, not to
	// its value, so they would keep refreshing under the new value forever, and a
	// consented code not yet exchanged would mint a fresh grant after the fact.
	// Rotation is the response to a value that may have leaked, and everything
	// obtained with that value has to go with it; the cooldown applies to the
	// retired value itself, not to what was minted from it. Revoking the grants
	// and storing the new value commit in one transaction: if either fails,
	// neither happens, and in-memory governance is reloaded only after commit.
	if err := r.configStore.ExecuteTransaction(ctx, func(tx *gorm.DB) error {
		if err := r.configStore.RevokeOAuth2GrantsBySubject(ctx, string(schemas.MCPAuthModeVK), vk.ID, tx); err != nil {
			return fmt.Errorf("failed to revoke the virtual key's MCP OAuth grants, rotation aborted: %w", err)
		}
		if immediate {
			if store, ok := r.configStore.(interface {
				UpdateVirtualKeyCredential(context.Context, *configstoreTables.TableVirtualKey, string, *gorm.DB) error
			}); ok {
				return store.UpdateVirtualKeyCredential(ctx, vk, expectedHash, tx)
			}
		}
		return r.configStore.UpdateVirtualKey(ctx, vk, tx)
	}); err != nil {
		return nil, err
	}
	committed = true
	if schemas.VaultStoreWriteEnabled() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if failures := schemas.RemoveOwnedVaultSecretVars(cleanup, base, &retiredSecrets); len(failures) > 0 {
			logger.Warn("failed to clean up retired virtual-key Vault credentials")
		}
		cancel()
	}
	preloadedVk, err := r.governanceManager.ReloadVirtualKey(ctx, vk.ID)
	if err != nil {
		return nil, fmt.Errorf("virtual key rotated in database but failed to reload in-memory state: %w", err)
	}
	if preloadedVk == nil || preloadedVk.Value.GetValue() != issuedValue {
		return nil, fmt.Errorf("virtual key changed during rotation; rotate again to obtain a new credential")
	}
	hydrateVKGovernanceFromStore(ctx, r.configStore, preloadedVk)
	return preloadedVk, nil
}
