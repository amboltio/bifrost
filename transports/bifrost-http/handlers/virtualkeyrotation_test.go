package handlers

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/configstore"
	configstoreTables "github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/maximhq/bifrost/framework/encrypt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// rotationTestGovernanceManager reloads the rotated key straight from the
// store, which is all RotateVirtualKey needs from the manager here.
type rotationTestGovernanceManager struct {
	pricingOverrideTestGovernanceManager
	store configstore.ConfigStore
}

func (m rotationTestGovernanceManager) ReloadVirtualKey(ctx context.Context, id string) (*configstoreTables.TableVirtualKey, error) {
	return m.store.GetVirtualKey(ctx, id)
}

func newRotationTestStore(t *testing.T) *configstore.RDBConfigStore {
	t.Helper()
	store, err := configstore.NewConfigStore(context.Background(), &configstore.Config{
		Enabled: true,
		Type:    configstore.ConfigStoreTypeSQLite,
		Config:  &configstore.SQLiteConfig{Path: filepath.Join(t.TempDir(), "config.db")},
	}, testLogger{})
	require.NoError(t, err)
	t.Cleanup(func() { store.Close(context.Background()) })
	rdb, ok := store.(*configstore.RDBConfigStore)
	require.True(t, ok, "sqlite config store is the RDB implementation")
	return rdb
}

func TestImmediateRotationCredentialCASPreservesConcurrentSettings(t *testing.T) {
	store := newRotationTestStore(t)
	ctx := context.Background()
	active := true
	require.NoError(t, store.CreateVirtualKey(ctx, &configstoreTables.TableVirtualKey{ID: "cas-key", Name: "Original", Description: "Original settings", IsActive: &active, Value: *schemas.NewSecretVar("sk-bf-old-cas-credential")}))
	stale, err := store.GetVirtualKey(ctx, "cas-key")
	require.NoError(t, err)
	expected := stale.ValueHash
	current, err := store.GetVirtualKey(ctx, "cas-key")
	require.NoError(t, err)
	current.Name = "Concurrent rename"
	current.Description = "Concurrent description"
	require.NoError(t, store.UpdateVirtualKey(ctx, current))
	stale.Value = *schemas.NewSecretVar("sk-bf-new-cas-credential")
	now := time.Now().UTC()
	stale.RotatedAt = &now
	stale.ClearPreviousValue()
	require.NoError(t, store.ExecuteTransaction(ctx, func(tx *gorm.DB) error { return store.UpdateVirtualKeyCredential(ctx, stale, expected, tx) }))
	rotated, err := store.GetVirtualKey(ctx, "cas-key")
	require.NoError(t, err)
	assert.Equal(t, "Concurrent rename", rotated.Name)
	assert.Equal(t, "Concurrent description", rotated.Description)
	assert.Equal(t, "sk-bf-new-cas-credential", rotated.Value.GetValue())
	_, err = store.GetVirtualKeyQuotaByValue(ctx, "sk-bf-old-cas-credential")
	assert.ErrorIs(t, err, configstore.ErrNotFound)
	stale.Value = *schemas.NewSecretVar("sk-bf-losing-cas-credential")
	require.ErrorIs(t, store.ExecuteTransaction(ctx, func(tx *gorm.DB) error { return store.UpdateVirtualKeyCredential(ctx, stale, expected, tx) }), configstore.ErrNotFound)
	rotated, err = store.GetVirtualKey(ctx, "cas-key")
	require.NoError(t, err)
	assert.Equal(t, "sk-bf-new-cas-credential", rotated.Value.GetValue())
}

func seedRotationRefreshToken(t *testing.T, store *configstore.RDBConfigStore, id, bfMode, bfSub string) {
	t.Helper()
	require.NoError(t, store.DB().Create(&configstoreTables.TableOAuth2RefreshToken{
		ID:        id,
		TokenHash: "hash-" + id,
		FamilyID:  "family-" + id,
		ClientID:  "client",
		BfMode:    bfMode,
		BfSub:     bfSub,
		Scope:     "mcp",
		Resource:  "https://bifrost.test/mcp",
		CreatedAt: time.Now(),
	}).Error)
}

// TestRotateVirtualKeyRevokesItsOAuthGrants: a vk-mode MCP OAuth grant is bound
// to the key's row id, so it is only as retired as the rotation makes it. Rotating
// the value revokes every grant that key minted; grants of other keys and of
// other identity modes are untouched.
func TestRotateVirtualKeyRevokesItsOAuthGrants(t *testing.T) {
	store := newRotationTestStore(t)
	ctx := context.Background()
	active := true
	for _, id := range []string{"vk-rotated", "vk-other"} {
		require.NoError(t, store.CreateVirtualKey(ctx, &configstoreTables.TableVirtualKey{
			ID:       id,
			Name:     id,
			Value:    *schemas.NewSecretVar("sk-bf-" + id),
			IsActive: &active,
		}))
	}
	seedRotationRefreshToken(t, store, "grant-1", string(schemas.MCPAuthModeVK), "vk-rotated")
	seedRotationRefreshToken(t, store, "grant-2", string(schemas.MCPAuthModeVK), "vk-rotated")
	seedRotationRefreshToken(t, store, "grant-other-key", string(schemas.MCPAuthModeVK), "vk-other")
	seedRotationRefreshToken(t, store, "grant-user", string(schemas.MCPAuthModeUser), "vk-rotated")

	// A consented, not yet exchanged authorization code for the rotated key.
	require.NoError(t, store.DB().Create(&configstoreTables.TableOAuth2AuthorizeRequest{
		ID: "ar-rotated", ClientID: "client", RedirectURI: "http://127.0.0.1/cb", State: "s", Scope: "mcp",
		Resource: "https://bifrost.test/mcp", CodeChallenge: "ch", CodeChallengeMethod: "S256",
		Status: configstoreTables.OAuth2AuthorizeRequestStatusConsented, CodeHash: schemas.Ptr("code-rotated"),
		BfMode: string(schemas.MCPAuthModeVK), BfSub: "vk-rotated",
		ExpiresAt: time.Now().Add(time.Minute), CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}).Error)

	rotator := NewVirtualKeyRotator(store, rotationTestGovernanceManager{store: store})
	rotated, err := rotator.RotateVirtualKey(ctx, "vk-rotated")
	require.NoError(t, err)

	// The pending code cannot be exchanged for a fresh grant under the new value.
	err = store.ConsumeOAuth2AuthorizeRequest(ctx, "ar-rotated", &configstoreTables.TableOAuth2RefreshToken{
		ID: "grant-late", TokenHash: "hash-grant-late", FamilyID: "ar-rotated", ClientID: "client",
		BfMode: string(schemas.MCPAuthModeVK), BfSub: "vk-rotated", Scope: "mcp", Resource: "https://bifrost.test/mcp", CreatedAt: time.Now(),
	})
	assert.ErrorIs(t, err, configstore.ErrNotFound)
	assert.NotEqual(t, "sk-bf-vk-rotated", rotated.Value.GetValue(), "the value is rotated as before")

	// Both of the rotated key's grants are revoked...
	_, err = store.GetOAuth2RefreshTokenByHash(ctx, "hash-grant-1")
	assert.ErrorIs(t, err, configstore.ErrNotFound)
	_, err = store.GetOAuth2RefreshTokenByHash(ctx, "hash-grant-2")
	assert.ErrorIs(t, err, configstore.ErrNotFound)
	// ...and the rows are kept as revoked rather than deleted, so replay detection still works.
	revoked, err := store.GetOAuth2RefreshTokenByHashAny(ctx, "hash-grant-1")
	require.NoError(t, err)
	assert.NotNil(t, revoked.RevokedAt)

	// Another key's grant and a user-mode grant survive.
	_, err = store.GetOAuth2RefreshTokenByHash(ctx, "hash-grant-other-key")
	require.NoError(t, err)
	_, err = store.GetOAuth2RefreshTokenByHash(ctx, "hash-grant-user")
	require.NoError(t, err)
}

// TestRotateVirtualKeyLeavesKeyUntouchedWhenGrantRevocationFails: grant revocation
// runs before the key value is persisted, so a store failure there leaves the key,
// the database and in-memory governance exactly as they were.
func TestRotateVirtualKeyLeavesKeyUntouchedWhenGrantRevocationFails(t *testing.T) {
	SetLogger(&mockLogger{})
	active := true
	store := &mockRotateConfigStore{
		virtualKeys: map[string]*configstoreTables.TableVirtualKey{
			"vk-1": {ID: "vk-1", Name: "Production", Value: *schemas.NewSecretVar("sk-bf-old"), IsActive: &active},
		},
		revokeErr: errors.New("grants table unavailable"),
	}
	manager := &mockRotateGovernanceManager{store: store}

	_, err := NewVirtualKeyRotator(store, manager).RotateVirtualKey(context.Background(), "vk-1")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "grants table unavailable")
	assert.Equal(t, 0, store.updates, "the key value must not be persisted when its grants could not be revoked")
	assert.Equal(t, "sk-bf-old", store.virtualKeys["vk-1"].Value.GetValue())
}

// failingUpdateStore is a real SQLite config store whose virtual-key update fails, standing in for
// any write error that lands after grant revocation has already run.
type failingUpdateStore struct {
	*configstore.RDBConfigStore
}

func (s failingUpdateStore) UpdateVirtualKey(context.Context, *configstoreTables.TableVirtualKey, ...*gorm.DB) error {
	return errors.New("virtual key write failed")
}

// TestRotateVirtualKeyRollsBackGrantRevocationWhenKeyUpdateFails: revoking the key's grants and
// storing its new value commit together. If the key cannot be stored, the grants are not revoked
// either, so the database never holds the old key with its grants gone.
func TestRotateVirtualKeyRollsBackGrantRevocationWhenKeyUpdateFails(t *testing.T) {
	rdb := newRotationTestStore(t)
	ctx := context.Background()
	active := true
	require.NoError(t, rdb.CreateVirtualKey(ctx, &configstoreTables.TableVirtualKey{
		ID: "vk-rotated", Name: "vk-rotated", Value: *schemas.NewSecretVar("sk-bf-vk-rotated"), IsActive: &active,
	}))
	seedRotationRefreshToken(t, rdb, "grant-1", string(schemas.MCPAuthModeVK), "vk-rotated")

	store := failingUpdateStore{rdb}
	_, err := NewVirtualKeyRotator(store, rotationTestGovernanceManager{store: rdb}).RotateVirtualKey(ctx, "vk-rotated")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "virtual key write failed")
	_, err = rdb.GetOAuth2RefreshTokenByHash(ctx, "hash-grant-1")
	assert.NoError(t, err, "the grant must survive a rotation that did not store the new key")
	stored, err := rdb.GetVirtualKey(ctx, "vk-rotated")
	require.NoError(t, err)
	assert.Equal(t, "sk-bf-vk-rotated", stored.Value.GetValue())
}

// rotationTestVault models the external side effect that SQL rollback cannot undo.
// Every read resolves the actual stored reference, so a hash/ref mismatch is visible.
type rotationTestVault struct {
	values  map[string]string
	writes  []string
	removed []string
}

func newRotationTestVault(t *testing.T) *rotationTestVault {
	t.Helper()
	vault := &rotationTestVault{values: make(map[string]string)}
	oldStore, oldResolve, oldRemove := schemas.VaultStoreHook, schemas.VaultResolveHook, schemas.VaultRemoveHook
	schemas.VaultStoreHook = func(_ context.Context, path string, value *string) error {
		vault.values[path] = *value
		vault.writes = append(vault.writes, path)
		*value = "vault." + path
		return nil
	}
	schemas.VaultResolveHook = func(_ context.Context, value *string) error {
		path := strings.TrimPrefix(*value, "vault.")
		secret, exists := vault.values[path]
		if !exists {
			return errors.New("test vault reference not found")
		}
		*value = secret
		return nil
	}
	schemas.VaultRemoveHook = func(_ context.Context, path string) error {
		delete(vault.values, path)
		vault.removed = append(vault.removed, path)
		return nil
	}
	t.Cleanup(func() {
		schemas.VaultStoreHook, schemas.VaultResolveHook, schemas.VaultRemoveHook = oldStore, oldResolve, oldRemove
	})
	return vault
}

func seedVaultRotationKey(t *testing.T, store *configstore.RDBConfigStore, id string, previous bool) *configstoreTables.TableVirtualKey {
	t.Helper()
	key := &configstoreTables.TableVirtualKey{
		ID: id, Name: id, IsActive: schemas.Ptr(true),
		Value: *schemas.NewSecretVar("sk-bf-original-vault-credential"),
	}
	if previous {
		key.PreviousValue = *schemas.NewSecretVar("sk-bf-older-vault-credential")
		key.PreviousValueExpiresAt = schemas.Ptr(time.Now().Add(time.Hour))
	}
	require.NoError(t, store.CreateVirtualKey(context.Background(), key))
	loaded, err := store.GetVirtualKey(context.Background(), id)
	require.NoError(t, err)
	require.True(t, loaded.Value.IsFromVault())
	require.Equal(t, "sk-bf-original-vault-credential", loaded.Value.GetValue())
	return loaded
}

func TestImmediateVaultRotationSQLFailurePreservesOriginalSecret(t *testing.T) {
	vault := newRotationTestVault(t)
	store := newRotationTestStore(t)
	ctx := context.Background()
	original := seedVaultRotationKey(t, store, "vault-rollback", false)
	originalPath := original.Value.GetRef()
	initialWrites := len(vault.writes)
	seedRotationRefreshToken(t, store, "vault-rollback-grant", string(schemas.MCPAuthModeVK), original.ID)

	writeFailure := errors.New("injected failure after credential SQL update")
	wroteCredential := false
	require.NoError(t, store.DB().Callback().Update().After("gorm:update").Register("test:vault_rotation_sql_failure", func(tx *gorm.DB) {
		if tx.Statement.Table == original.TableName() && tx.Error == nil && tx.RowsAffected == 1 {
			wroteCredential = true
			tx.AddError(writeFailure)
		}
	}))
	t.Cleanup(func() { store.DB().Callback().Update().Remove("test:vault_rotation_sql_failure") })

	_, err := NewVirtualKeyRotator(store, rotationTestGovernanceManager{store: store}).RotateVirtualKeyImmediately(ctx, original.ID)
	require.Error(t, err)
	assert.ErrorContains(t, err, writeFailure.Error())
	require.True(t, wroteCredential, "failure must occur after SQL updated the row, not before its Vault hook")
	assert.Equal(t, original.Value.GetValue(), vault.values[originalPath], "rollback must not overwrite the original external secret")
	require.Greater(t, len(vault.writes), initialWrites)
	for _, path := range vault.writes[initialWrites:] {
		assert.NotEqual(t, originalPath, path)
		assert.Contains(t, path, "/rotations/")
		assert.NotContains(t, vault.values, path, "failed issuance must not leave an allocated secret")
		assert.Contains(t, vault.removed, path)
	}
	assert.NotContains(t, vault.removed, originalPath)
	stored, err := store.GetVirtualKey(ctx, original.ID)
	require.NoError(t, err)
	assert.Equal(t, original.Value.GetRawRef(), stored.Value.GetRawRef())
	assert.Equal(t, original.ValueHash, stored.ValueHash)
	assert.Equal(t, original.Value.GetValue(), stored.Value.GetValue())
	_, err = store.GetOAuth2RefreshTokenByHash(ctx, "hash-vault-rollback-grant")
	assert.NoError(t, err, "grant revocation must roll back with the credential")
}

func TestImmediateVaultRotationPersistsMatchingHashAndRemovesRetiredRefs(t *testing.T) {
	vault := newRotationTestVault(t)
	store := newRotationTestStore(t)
	ctx := context.Background()
	original := seedVaultRotationKey(t, store, "vault-success", true)
	oldPaths := []string{original.Value.GetRef(), original.PreviousValue.GetRef()}
	for _, path := range oldPaths {
		require.Contains(t, vault.values, path)
	}

	rotated, err := NewVirtualKeyRotator(store, rotationTestGovernanceManager{store: store}).RotateVirtualKeyImmediately(ctx, original.ID)
	require.NoError(t, err)
	require.True(t, rotated.Value.IsFromVault())
	assert.NotEqual(t, original.Value.GetRawRef(), rotated.Value.GetRawRef())
	assert.Contains(t, rotated.Value.GetRef(), "/rotations/")
	assert.NotEqual(t, original.Value.GetValue(), rotated.Value.GetValue())
	assert.Equal(t, rotated.Value.GetValue(), vault.values[rotated.Value.GetRef()])
	assert.Equal(t, encrypt.HashSHA256(rotated.Value.GetValue()), rotated.ValueHash, "hash must cover the resolved secret, not its Vault reference")
	assert.False(t, rotated.PreviousValue.IsSet())
	for _, path := range oldPaths {
		assert.NotContains(t, vault.values, path)
		assert.Contains(t, vault.removed, path)
	}
	assert.NotContains(t, vault.removed, rotated.Value.GetRef())
	_, err = store.GetVirtualKeyQuotaByValue(ctx, original.Value.GetValue())
	assert.ErrorIs(t, err, configstore.ErrNotFound)
	authenticated, err := store.GetVirtualKeyQuotaByValue(ctx, rotated.Value.GetValue())
	require.NoError(t, err)
	assert.Equal(t, original.ID, authenticated.ID)
}

type failedVaultRotationReload struct{ rotationTestGovernanceManager }

func (failedVaultRotationReload) ReloadVirtualKey(context.Context, string) (*configstoreTables.TableVirtualKey, error) {
	return nil, errors.New("injected in-memory reload failure")
}

func TestImmediateVaultRotationRetainsCommittedSecretOnReloadFailure(t *testing.T) {
	vault := newRotationTestVault(t)
	store := newRotationTestStore(t)
	ctx := context.Background()
	original := seedVaultRotationKey(t, store, "vault-reload-failure", false)
	manager := failedVaultRotationReload{rotationTestGovernanceManager{store: store}}

	_, err := NewVirtualKeyRotator(store, manager).RotateVirtualKeyImmediately(ctx, original.ID)
	require.ErrorContains(t, err, "failed to reload in-memory state")
	stored, err := store.GetVirtualKey(ctx, original.ID)
	require.NoError(t, err)
	require.True(t, stored.Value.IsFromVault())
	assert.NotEqual(t, original.Value.GetRawRef(), stored.Value.GetRawRef())
	assert.NotEqual(t, original.Value.GetValue(), stored.Value.GetValue())
	assert.NotEmpty(t, stored.Value.GetValue(), "committed reference must still resolve after reload failure")
	assert.Equal(t, stored.Value.GetValue(), vault.values[stored.Value.GetRef()])
	assert.Equal(t, encrypt.HashSHA256(stored.Value.GetValue()), stored.ValueHash)
	assert.NotContains(t, vault.removed, stored.Value.GetRef(), "reload failure must not run rollback cleanup after commit")
	_, err = store.GetVirtualKeyQuotaByValue(ctx, stored.Value.GetValue())
	assert.NoError(t, err, "a later successful reload must be able to recover the committed credential")
}
