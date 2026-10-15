package configstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/maximhq/bifrost/framework/encrypt"
	"gorm.io/gorm"
)

type DashboardIdentityState struct {
	Initialized bool `json:"initialized"`
}
type DashboardIdentityStateStore interface {
	GetDashboardIdentityState(context.Context) (DashboardIdentityState, error)
}

type DashboardAuthPolicy struct {
	Revision   uint64     `json:"revision"`
	AuthConfig AuthConfig `json:"auth_config"`
}

type storedDashboardPolicy struct {
	Encrypted bool   `json:"encrypted"`
	Payload   string `json:"payload"`
}

var ErrAuthPolicyConflict = errors.New("authentication settings changed; reload and retry")

func (s *RDBConfigStore) GetDashboardIdentityState(ctx context.Context) (DashboardIdentityState, error) {
	return dashboardIdentityState(s.DB().WithContext(ctx))
}

func dashboardIdentityState(tx *gorm.DB) (DashboardIdentityState, error) {
	var row tables.TableGovernanceConfig
	err := tx.First(&row, "key = ?", tables.ConfigDashboardInitializedKey).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return DashboardIdentityState{}, nil
	}
	if err != nil {
		return DashboardIdentityState{}, err
	}
	if row.Value != "true" {
		return DashboardIdentityState{}, fmt.Errorf("invalid dashboard initialization state")
	}
	return DashboardIdentityState{Initialized: true}, nil
}

func markDashboardInitialized(tx *gorm.DB) error {
	return tx.Save(&tables.TableGovernanceConfig{Key: tables.ConfigDashboardInitializedKey, Value: "true"}).Error
}

func (s *RDBConfigStore) GetDashboardAuthPolicy(ctx context.Context) (*DashboardAuthPolicy, error) {
	return readDashboardPolicy(s.DB().WithContext(ctx))
}

func readDashboardPolicy(tx *gorm.DB) (*DashboardAuthPolicy, error) {
	var row tables.TableGovernanceConfig
	if err := tx.First(&row, "key = ?", tables.ConfigDashboardAuthPolicyKey).Error; err != nil {
		return nil, err
	}
	var stored storedDashboardPolicy
	if err := json.Unmarshal([]byte(row.Value), &stored); err != nil {
		return nil, fmt.Errorf("invalid dashboard policy: %w", err)
	}
	payload := stored.Payload
	if stored.Encrypted {
		var err error
		payload, err = encrypt.Decrypt(payload)
		if err != nil {
			return nil, err
		}
	}
	var policy DashboardAuthPolicy
	if err := json.Unmarshal([]byte(payload), &policy); err != nil {
		return nil, err
	}
	if policy.Revision == 0 {
		return nil, fmt.Errorf("invalid dashboard policy revision")
	}
	return &policy, nil
}

func writeDashboardPolicy(tx *gorm.DB, config *AuthConfig, revision uint64) error {
	if config == nil {
		return fmt.Errorf("authentication settings are required")
	}
	copy := config.Normalized()
	copy.OIDCProviders = append([]OIDCProviderConfig(nil), copy.OIDCProviders...)
	// Persist references, never the environment/vault values resolved in memory.
	referenceOnly := func(v *schemas.SecretVar) *schemas.SecretVar {
		if v == nil || !v.IsFromSecret() {
			return v
		}
		ref := *v
		ref.Val = ""
		return &ref
	}
	copy.AdminUserName = referenceOnly(copy.AdminUserName)
	copy.AdminPassword = referenceOnly(copy.AdminPassword)
	for i := range copy.OIDCProviders {
		copy.OIDCProviders[i].ClientID = referenceOnly(copy.OIDCProviders[i].ClientID)
		copy.OIDCProviders[i].ClientSecret = referenceOnly(copy.OIDCProviders[i].ClientSecret)
	}
	payload, err := json.Marshal(DashboardAuthPolicy{Revision: revision, AuthConfig: copy})
	if err != nil {
		return err
	}
	stored := storedDashboardPolicy{Payload: string(payload)}
	// Without an encryption key Encrypt returns the plaintext unchanged, so the
	// row must not be flagged encrypted or Decrypt would reject it on read.
	if encrypt.IsEnabled() {
		encrypted, err := encrypt.Encrypt(stored.Payload)
		if err != nil {
			return err
		}
		stored.Payload, stored.Encrypted = encrypted, true
	}
	data, err := json.Marshal(stored)
	if err != nil {
		return err
	}
	return tx.Save(&tables.TableGovernanceConfig{Key: tables.ConfigDashboardAuthPolicyKey, Value: string(data)}).Error
}

// SaveDashboardAuthPolicy serializes policy changes with role/user mutations.
// Audit, session revocation, policy and revision commit as one unit.
func (s *RDBConfigStore) SaveDashboardAuthPolicy(ctx context.Context, revision uint64, config *AuthConfig, audit *tables.TableAuditEvent, outbox *tables.TableOutboxEvent) error {
	if config == nil || !config.IsEnabled || config.AdminUserName != nil || config.AdminPassword != nil {
		return fmt.Errorf("dashboard requires user login; shared credentials are not allowed")
	}
	if err := config.Validate(); err != nil {
		return err
	}
	return s.ApplyAuditedChange(ctx, audit, outbox, func(tx *gorm.DB) error {
		if err := lockSuperAdminRole(tx); err != nil {
			return err
		}
		state, err := dashboardIdentityState(tx)
		if err != nil {
			return err
		}
		if !state.Initialized {
			return fmt.Errorf("dashboard setup is incomplete")
		}
		current, err := readDashboardPolicy(tx)
		if err != nil {
			return err
		}
		if current.Revision != revision {
			return ErrAuthPolicyConflict
		}
		if err := requireUsableDashboardAdmin(tx, config); err != nil {
			return err
		}
		if err := writeDashboardPolicy(tx, config, revision+1); err != nil {
			return err
		}
		return tx.Model(&tables.SessionsTable{}).Where("revoked_at IS NULL").Update("revoked_at", time.Now().UTC()).Error
	})
}

func requireUsableDashboardAdmin(tx *gorm.DB, config *AuthConfig) error {
	var users []tables.TableUser
	if err := tx.Model(&tables.TableUser{}).
		Joins("JOIN identity_role_assignments ON identity_role_assignments.user_id = identity_users.id").
		Where("identity_users.status = ? AND identity_role_assignments.role_id = ?", tables.UserStatusActive, tables.RoleIDSuperAdmin).
		Find(&users).Error; err != nil {
		return err
	}
	for _, user := range users {
		if config.localLoginEnabled() {
			var count int64
			if err := tx.Model(&tables.TableCredential{}).Where("user_id = ? AND is_active = ? AND kind IN ?", user.ID, true, []string{tables.CredentialKindPassword, tables.CredentialKindLegacyPassword}).Count(&count).Error; err != nil {
				return err
			}
			if count > 0 {
				return nil
			}
		}
		for _, provider := range config.EnabledOIDCProviders() {
			var count int64
			if err := tx.Model(&tables.TableExternalIdentity{}).Where("user_id = ? AND is_active = ? AND provider_id = ? AND issuer = ?", user.ID, true, provider.ID, provider.IssuerURL).Count(&count).Error; err != nil {
				return err
			}
			if count > 0 {
				return nil
			}
		}
	}
	return fmt.Errorf("at least one active administrator must retain a usable login method")
}

func checkDashboardAdminAfterMutation(tx *gorm.DB) error {
	state, err := dashboardIdentityState(tx)
	if err != nil {
		return err
	}
	if !state.Initialized {
		return nil
	}
	policy, err := readDashboardPolicy(tx)
	if err != nil {
		return err
	}
	return requireUsableDashboardAdmin(tx, &policy.AuthConfig)
}
