package configstore

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"gorm.io/gorm"
)

// OIDCTransactionStore is the narrow persistence contract needed by the OIDC
// login service. A database transaction row allows callback processing to
// survive process restarts and makes state single-use across every replica.
type OIDCTransactionStore interface {
	CreateOIDCTransaction(ctx context.Context, transaction *tables.TableOIDCTransaction) error
	ClaimOIDCTransaction(ctx context.Context, stateHash string, now time.Time) (*tables.TableOIDCTransaction, error)
	DeleteExpiredOIDCTransactions(ctx context.Context, now time.Time) (int64, error)
}

// OIDCProvisioningStore creates a verified, first-time OIDC user and its
// external binding atomically. Implementations must assign the least
// privileged role and record the creation in the identity journal.
type OIDCProvisioningStore interface {
	ProvisionOIDCIdentity(ctx context.Context, user *tables.TableUser, external *tables.TableExternalIdentity, roleID string) (*tables.TableUser, error)
}

// ProvisionOIDCIdentity creates a JIT-provisioned user, viewer assignment,
// external subject binding, audit event, and invalidation outbox row in one
// transaction. Existing email rows are rejected by the canonical unique index;
// a verified email never silently merges two accounts.
func (s *RDBConfigStore) ProvisionOIDCIdentity(ctx context.Context, user *tables.TableUser, external *tables.TableExternalIdentity, roleID string) (*tables.TableUser, error) {
	if user == nil || external == nil || user.Email == nil || !user.EmailVerified {
		return nil, fmt.Errorf("verified OIDC email is required for provisioning")
	}
	roleID = strings.TrimSpace(roleID)
	if roleID == "" {
		roleID = "viewer"
	}
	if user.ID == "" {
		user.ID = uuid.NewString()
	}
	external.UserID = user.ID
	if external.ID == "" {
		external.ID = uuid.NewString()
	}
	targetID := user.ID
	audit := &tables.TableAuditEvent{
		ID: uuid.NewString(), ActorPrincipal: "anonymous:oidc", TargetType: "user", TargetID: &targetID,
		Action: "identity.user.created", OccurredAt: time.Now().UTC(),
		ChangedFields: map[string]any{"auth_method": "oidc", "provider_id": external.ProviderID, "email_verified": true, "role_ids": []string{roleID}},
	}
	outbox := &tables.TableOutboxEvent{
		ID: uuid.NewString(), Topic: "identity.user.changed", DeduplicationKey: "identity.user:" + audit.ID,
		AvailableAt: time.Now().UTC(), Payload: map[string]any{"user_id": user.ID, "action": audit.Action},
	}
	err := s.ApplyAuditedChange(ctx, audit, outbox, func(tx *gorm.DB) error {
		var role tables.TableRole
		if err := tx.Where("id = ?", roleID).First(&role).Error; err != nil {
			return err
		}
		user.Status = tables.UserStatusActive
		if err := s.CreateUser(ctx, user, tx); err != nil {
			return err
		}
		if err := s.AssignRole(ctx, &tables.TableRoleAssignment{ID: uuid.NewString(), UserID: user.ID, RoleID: role.ID}, tx); err != nil {
			return err
		}
		return s.CreateExternalIdentity(ctx, external, tx)
	})
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (s *RDBConfigStore) CreateOIDCTransaction(ctx context.Context, transaction *tables.TableOIDCTransaction) error {
	if transaction == nil {
		return fmt.Errorf("OIDC transaction cannot be nil")
	}
	if transaction.ID == "" {
		transaction.ID = uuid.NewString()
	}
	if err := s.DB().WithContext(ctx).Create(transaction).Error; err != nil {
		return s.parseGormError(err)
	}
	return nil
}

// ClaimOIDCTransaction atomically consumes an unexpired state. A callback
// which arrives twice, is expired, or is unknown returns nil without leaking
// which condition occurred to the browser.
func (s *RDBConfigStore) ClaimOIDCTransaction(ctx context.Context, stateHash string, now time.Time) (*tables.TableOIDCTransaction, error) {
	stateHash = strings.TrimSpace(stateHash)
	if stateHash == "" {
		return nil, nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}

	var transaction tables.TableOIDCTransaction
	err := s.DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&tables.TableOIDCTransaction{}).
			Where("state_hash = ? AND consumed_at IS NULL AND expires_at > ?", stateHash, now).
			Update("consumed_at", now)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return nil
		}
		return tx.Where("state_hash = ? AND consumed_at = ?", stateHash, now).First(&transaction).Error
	})
	if err != nil {
		return nil, err
	}
	if transaction.ID == "" {
		return nil, nil
	}
	return &transaction, nil
}

func (s *RDBConfigStore) DeleteExpiredOIDCTransactions(ctx context.Context, now time.Time) (int64, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	result := s.DB().WithContext(ctx).Where("expires_at <= ?", now.UTC()).Delete(&tables.TableOIDCTransaction{})
	if result.Error != nil {
		return 0, result.Error
	}
	return result.RowsAffected, nil
}
