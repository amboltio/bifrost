package configstore

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/maximhq/bifrost/framework/configstore/tables"
	"gorm.io/gorm"
)

// ExternalIdentityManagementStore is the protected administrator contract for
// inspecting and revoking external login bindings. Linking remains a verified
// OIDC callback operation; this surface cannot attach an unverified subject.
type ExternalIdentityManagementStore interface {
	ListExternalIdentitiesByUserID(ctx context.Context, userID string) ([]tables.TableExternalIdentity, error)
	SetExternalIdentityActiveAudited(ctx context.Context, userID, identityID string, isActive bool, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) error
}

// LinkExternalIdentity records an issuer/subject only after the OIDC service
// has validated its signature, issuer, audience, nonce, and state. A subject
// already owned by another user is rejected by the unique constraint and the
// explicit ownership check below.
func (s *RDBConfigStore) LinkExternalIdentity(ctx context.Context, userID string, external *tables.TableExternalIdentity) error {
	if strings.TrimSpace(userID) == "" || external == nil {
		return ErrNotFound
	}
	if strings.TrimSpace(external.Issuer) == "" || strings.TrimSpace(external.Subject) == "" || strings.TrimSpace(external.ProviderID) == "" {
		return ErrNotFound
	}
	targetID := userID
	audit := &tables.TableAuditEvent{
		ActorPrincipal: "user:" + userID, TargetType: "user", TargetID: &targetID,
		Action: "identity.user.external_identity_linked", OccurredAt: time.Now().UTC(),
		ChangedFields: map[string]any{"provider_id": external.ProviderID, "issuer": external.Issuer, "subject": external.Subject},
	}
	outbox := &tables.TableOutboxEvent{
		Topic: "identity.user.changed", DeduplicationKey: "identity.user:external-link:" + userID + ":" + external.Issuer + ":" + external.Subject,
		AvailableAt: time.Now().UTC(), Payload: map[string]any{"user_id": userID, "action": audit.Action},
	}
	return s.ApplyAuditedChange(ctx, audit, outbox, func(tx *gorm.DB) error {
		user, err := lockedUser(tx, userID)
		if err != nil {
			return err
		}
		if user.Status != tables.UserStatusActive {
			return ErrNotFound
		}
		var existing tables.TableExternalIdentity
		err = dbForUpdate(tx).Where("issuer = ? AND subject = ?", strings.TrimSpace(external.Issuer), strings.TrimSpace(external.Subject)).First(&existing).Error
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			external.UserID = userID
			external.IsActive = true
			return s.CreateExternalIdentity(ctx, external, tx)
		case err != nil:
			return err
		case existing.UserID != userID:
			return ErrAlreadyExists
		default:
			if err := tx.Model(&tables.TableExternalIdentity{}).Where("id = ?", existing.ID).Updates(map[string]any{"provider_id": external.ProviderID, "is_active": true}).Error; err != nil {
				return err
			}
			external.ID = existing.ID
			external.UserID = userID
			external.IsActive = true
			return nil
		}
	})
}

func (s *RDBConfigStore) ListExternalIdentitiesByUserID(ctx context.Context, userID string) ([]tables.TableExternalIdentity, error) {
	if strings.TrimSpace(userID) == "" {
		return []tables.TableExternalIdentity{}, nil
	}
	var identities []tables.TableExternalIdentity
	if err := s.DB().WithContext(ctx).Where("user_id = ?", userID).Order("provider_id ASC, issuer ASC, subject ASC").Find(&identities).Error; err != nil {
		return nil, err
	}
	return identities, nil
}

func (s *RDBConfigStore) SetExternalIdentityActiveAudited(ctx context.Context, userID, identityID string, isActive bool, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) error {
	if strings.TrimSpace(userID) == "" || strings.TrimSpace(identityID) == "" {
		return ErrNotFound
	}
	return s.ApplyAuditedChange(ctx, auditEvent, outboxEvent, func(tx *gorm.DB) error {
		if _, err := lockedUser(tx, userID); err != nil {
			return err
		}
		var external tables.TableExternalIdentity
		if err := dbForUpdate(tx).Where("id = ? AND user_id = ?", identityID, userID).First(&external).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		if external.IsActive == isActive {
			return nil
		}
		if !isActive {
			var activeExternalCount int64
			if err := tx.Model(&tables.TableExternalIdentity{}).Where("user_id = ? AND is_active = ?", userID, true).Count(&activeExternalCount).Error; err != nil {
				return err
			}
			var activeCredentialCount int64
			if err := tx.Model(&tables.TableCredential{}).Where("user_id = ? AND is_active = ? AND kind IN ?", userID, true, []string{tables.CredentialKindPassword, tables.CredentialKindLegacyPassword}).Count(&activeCredentialCount).Error; err != nil {
				return err
			}
			if activeExternalCount <= 1 && activeCredentialCount == 0 {
				return ErrLastAuthenticationMethod
			}
		}
		if err := tx.Model(&tables.TableExternalIdentity{}).Where("id = ? AND user_id = ?", identityID, userID).Update("is_active", isActive).Error; err != nil {
			return err
		}
		if !isActive {
			now := time.Now().UTC()
			if err := tx.Model(&tables.TableUser{}).Where("id = ?", userID).Update("auth_version", gorm.Expr("auth_version + ?", 1)).Error; err != nil {
				return err
			}
			if err := tx.Model(&tables.SessionsTable{}).Where("user_id = ? AND revoked_at IS NULL", userID).Update("revoked_at", now).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
