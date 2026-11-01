package configstore

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"

	"github.com/google/uuid"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"gorm.io/gorm"
)

// CreateLocalSuperAdmin is a trusted local operator mutation, never an HTTP
// bootstrap. It creates a distinct identity and preserves the durable policy.
// The initial policy is used only when no durable policy exists yet. All writes,
// including audit and invalidation, commit together. The work is CLI-only and
// adds no processing or retained memory to the inference request path.
func (s *RDBConfigStore) CreateLocalSuperAdmin(ctx context.Context, user *tables.TableUser, credential *tables.TableCredential, initialPolicy *AuthConfig) (*tables.TableUser, error) {
	if user == nil || user.Email == nil || credential == nil {
		return nil, fmt.Errorf("email and password credential are required")
	}
	email := strings.TrimSpace(*user.Email)
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email || !strings.Contains(email, "@") {
		return nil, fmt.Errorf("a valid email address is required")
	}
	if credential.Kind != tables.CredentialKindPassword || !credential.IsActive || !strings.HasPrefix(credential.SecretHash, "$argon2id$") {
		return nil, fmt.Errorf("an active Argon2id password credential is required")
	}
	created := *user
	created.ID, created.Email, created.Status, created.DisabledAt = uuid.NewString(), &email, tables.UserStatusActive, nil
	verifier := *credential
	verifier.ID, verifier.UserID, verifier.Version = uuid.NewString(), created.ID, 1
	eventID := uuid.NewString()
	audit := &tables.TableAuditEvent{ID: eventID, ActorPrincipal: "local-cli", TargetType: "user", TargetID: &created.ID, Action: "user.create_superadmin", ChangedFields: map[string]any{"role_id": tables.RoleIDSuperAdmin, "source": "createsuperadmin"}}
	outbox := &tables.TableOutboxEvent{Topic: "identity.user.changed", DeduplicationKey: "identity.user:" + eventID, Payload: map[string]any{"user_id": created.ID}}
	err = s.ApplyAuditedChange(ctx, audit, outbox, func(tx *gorm.DB) error {
		if err := lockSuperAdminRole(tx); err != nil {
			return err
		}
		policy, err := readDashboardPolicy(tx)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			policy = &DashboardAuthPolicy{}
			if initialPolicy != nil {
				policy.AuthConfig = initialPolicy.Normalized()
			}
		} else if err != nil {
			return err
		}
		var existing int64
		if err := tx.Model(&tables.TableUser{}).Where("normalized_email = ?", tables.NormalizeEmail(email)).Count(&existing).Error; err != nil {
			return err
		}
		if existing != 0 {
			return ErrAlreadyExists
		}
		if err := s.CreateUser(ctx, &created, tx); err != nil {
			return err
		}
		if err := s.CreateCredential(ctx, &verifier, tx); err != nil {
			return err
		}
		if err := s.AssignRole(ctx, &tables.TableRoleAssignment{ID: uuid.NewString(), UserID: created.ID, RoleID: tables.RoleIDSuperAdmin}, tx); err != nil {
			return err
		}
		config := policy.AuthConfig.Normalized()
		config.IsEnabled = true
		// Shared credentials are an upgrade input, never a new canonical login method.
		config.AdminUserName, config.AdminPassword = nil, nil
		if config.LocalLogin == nil {
			config.LocalLogin = &LocalLoginConfig{}
		}
		config.LocalLogin.IsEnabled = true
		if err := config.Validate(); err != nil {
			return err
		}
		if err := writeDashboardPolicy(tx, &config, policy.Revision+1); err != nil {
			return err
		}
		return markDashboardInitialized(tx)
	})
	if err != nil {
		return nil, err
	}
	return &created, nil
}
