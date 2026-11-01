package configstore

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/maximhq/bifrost/framework/authorization"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"gorm.io/gorm"
)

var ErrLocalPasswordUnavailable = errors.New("user has no active local password")

// ManagedPasswordStore replaces existing local credentials without creating
// a local sign-in method for an account managed solely by an identity provider.
type ManagedPasswordStore interface {
	ResetManagedPasswordAudited(context.Context, string, string, *string, time.Time, *tables.TableAuditEvent, *tables.TableOutboxEvent) error
}

// ResetManagedPasswordAudited keeps the replacement verifier, auth version,
// session and recovery-token revocation, audit and invalidation event atomic.
// User locks serialize this operation with role delegation and account changes.
func (s *RDBConfigStore) ResetManagedPasswordAudited(ctx context.Context, userID, newHash string, actorID *string, now time.Time, audit *tables.TableAuditEvent, outbox *tables.TableOutboxEvent) error {
	if strings.TrimSpace(userID) == "" || strings.TrimSpace(newHash) == "" {
		return ErrNotFound
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return s.ApplyAuditedChange(ctx, audit, outbox, func(tx *gorm.DB) error {
		_, actor, err := lockRoleAssignmentUsers(tx, userID, actorID)
		if err != nil {
			return err
		}
		if actor != nil {
			if actor.Status != tables.UserStatusActive {
				return ErrRoleDelegationDenied
			}
			var roles []tables.TableRole
			if err := tx.Model(&tables.TableRole{}).Joins("JOIN identity_role_assignments ON identity_role_assignments.role_id = identity_roles.id").Where("identity_role_assignments.user_id = ?", actor.ID).Find(&roles).Error; err != nil {
				return err
			}
			isSuperAdmin := slices.ContainsFunc(roles, func(role tables.TableRole) bool { return role.ID == tables.RoleIDSuperAdmin })
			if !isSuperAdmin {
				if !slices.ContainsFunc(roles, func(role tables.TableRole) bool {
					return slices.Contains(role.Permissions, string(authorization.PermissionUsersResetPassword))
				}) {
					return ErrRoleDelegationDenied
				}
				var count int64
				if err := tx.Model(&tables.TableRoleAssignment{}).Where("user_id = ? AND role_id = ?", userID, tables.RoleIDSuperAdmin).Count(&count).Error; err != nil {
					return err
				}
				if count != 0 {
					return ErrRoleDelegationDenied
				}
			}
		}
		var credentials []tables.TableCredential
		if err := dbForUpdate(tx).Where("user_id = ? AND is_active = ? AND kind IN ?", userID, true, []string{tables.CredentialKindPassword, tables.CredentialKindLegacyPassword}).Find(&credentials).Error; err != nil {
			return err
		}
		if len(credentials) == 0 {
			return ErrLocalPasswordUnavailable
		}
		// Replace all active local verifiers, including any legacy verifier, so
		// neither format can retain the old password. No identity is activated.
		for _, credential := range credentials {
			result := tx.Model(&tables.TableCredential{}).Where("id = ? AND version = ? AND is_active = ?", credential.ID, credential.Version, true).Updates(map[string]any{"secret_hash": newHash, "version": gorm.Expr("version + ?", 1)})
			if result.Error != nil {
				return result.Error
			}
			if result.RowsAffected != 1 {
				return ErrNotFound
			}
		}
		if err := tx.Model(&tables.TableUser{}).Where("id = ?", userID).Update("auth_version", gorm.Expr("auth_version + ?", 1)).Error; err != nil {
			return err
		}
		if err := tx.Model(&tables.SessionsTable{}).Where("user_id = ? AND revoked_at IS NULL", userID).Update("revoked_at", now.UTC()).Error; err != nil {
			return err
		}
		return tx.Model(&tables.TableRecoveryToken{}).Where("user_id = ? AND consumed_at IS NULL", userID).Update("consumed_at", now.UTC()).Error
	})
}
