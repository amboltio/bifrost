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
