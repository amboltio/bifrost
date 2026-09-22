package configstore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func (s *RDBConfigStore) identityDB(tx []*gorm.DB) *gorm.DB {
	if len(tx) > 0 && tx[0] != nil {
		return tx[0]
	}
	return s.DB()
}

// CreateUser inserts one canonical person. The unique normalized-email index
// is the authority for duplicate prevention, including across replicas.
func (s *RDBConfigStore) CreateUser(ctx context.Context, user *tables.TableUser, tx ...*gorm.DB) error {
	if user == nil {
		return fmt.Errorf("user cannot be nil")
	}
	if user.ID == "" {
		user.ID = uuid.NewString()
	}
	if err := s.identityDB(tx).WithContext(ctx).Create(user).Error; err != nil {
		return s.parseGormError(err)
	}
	return nil
}

// GetUser loads a durable user by stable ID.
func (s *RDBConfigStore) GetUser(ctx context.Context, id string) (*tables.TableUser, error) {
	var user tables.TableUser
	if err := s.DB().WithContext(ctx).First(&user, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

// GetUserByNormalizedEmail provides case-insensitive local-login lookup.
func (s *RDBConfigStore) GetUserByNormalizedEmail(ctx context.Context, email string) (*tables.TableUser, error) {
	normalized := tables.NormalizeEmail(email)
	if normalized == "" {
		return nil, nil
	}
	var user tables.TableUser
	if err := s.DB().WithContext(ctx).First(&user, "normalized_email = ?", normalized).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

// GetUserByLegacyUsername supports the transitional administrator mapping for
// deployments whose original dashboard username was not an email address.
func (s *RDBConfigStore) GetUserByLegacyUsername(ctx context.Context, username string) (*tables.TableUser, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, nil
	}
	var user tables.TableUser
	if err := s.DB().WithContext(ctx).First(&user, "legacy_username = ?", username).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

// UpdateUser persists profile fields through the model hook so email lookup
// normalization remains identical for creates and updates.
func (s *RDBConfigStore) UpdateUser(ctx context.Context, user *tables.TableUser, tx ...*gorm.DB) error {
	if user == nil || user.ID == "" {
		return fmt.Errorf("user with an ID is required")
	}
	if err := s.identityDB(tx).WithContext(ctx).Save(user).Error; err != nil {
		return s.parseGormError(err)
	}
	return nil
}

// DisableUser is idempotent and increments AuthVersion exactly once. It
// serializes active super-admin removal on the durable role row, so concurrent
// disable requests cannot leave the deployment without an active operator.
// Existing sessions are revoked in the same transaction instead of waiting for
// their next request to notice the auth-version change.
func (s *RDBConfigStore) DisableUser(ctx context.Context, id string, disabledAt time.Time) error {
	if id == "" {
		return ErrNotFound
	}
	if disabledAt.IsZero() {
		disabledAt = time.Now().UTC()
	}
	return s.DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return s.disableUser(ctx, tx, id, disabledAt)
	})
}

// DisableUserAudited keeps a soft-disable, its audit event, and the durable
// downstream invalidation signal indivisible.
func (s *RDBConfigStore) DisableUserAudited(ctx context.Context, id string, disabledAt time.Time, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) error {
	if id == "" {
		return ErrNotFound
	}
	if disabledAt.IsZero() {
		disabledAt = time.Now().UTC()
	}
	return s.ApplyAuditedChange(ctx, auditEvent, outboxEvent, func(tx *gorm.DB) error {
		return s.disableUser(ctx, tx, id, disabledAt)
	})
}

func (s *RDBConfigStore) disableUser(ctx context.Context, tx *gorm.DB, id string, disabledAt time.Time) error {
	user, err := lockedUser(tx, id)
	if err != nil {
		return err
	}
	if user.Status == tables.UserStatusDisabled {
		return nil
	}

	var superAdminAssignments int64
	if err := tx.Model(&tables.TableRoleAssignment{}).
		Where("user_id = ? AND role_id = ?", id, tables.RoleIDSuperAdmin).
		Count(&superAdminAssignments).Error; err != nil {
		return err
	}
	if user.Status == tables.UserStatusActive && superAdminAssignments > 0 {
		if err := lockSuperAdminRole(tx); err != nil {
			return err
		}
		if err := requireAnotherActiveSuperAdmin(tx); err != nil {
			return err
		}
	}

	result := tx.Model(&tables.TableUser{}).
		Where("id = ? AND status <> ?", id, tables.UserStatusDisabled).
		Updates(map[string]any{
			"status": tables.UserStatusDisabled, "disabled_at": disabledAt,
			"auth_version": gorm.Expr("auth_version + ?", 1),
		})
	if result.Error != nil {
		return s.parseGormError(result.Error)
	}
	if result.RowsAffected != 1 {
		return ErrNotFound
	}
	result = tx.Model(&tables.SessionsTable{}).
		Where("user_id = ? AND revoked_at IS NULL", id).
		Update("revoked_at", disabledAt.UTC())
	return result.Error
}

// CreateInitialSuperAdmin serializes first-user creation by locking the seeded
// immutable role. PostgreSQL obtains a row lock; SQLite serializes writers at
// the database level. A caller that loses the race receives ErrAlreadyExists.
func (s *RDBConfigStore) CreateInitialSuperAdmin(ctx context.Context, user *tables.TableUser, credential *tables.TableCredential) (*tables.TableUser, error) {
	if user == nil {
		return nil, fmt.Errorf("user cannot be nil")
	}
	if user.ID == "" {
		user.ID = uuid.NewString()
	}
	err := s.DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var role tables.TableRole
		if err := dbForUpdate(tx).First(&role, "id = ?", tables.RoleIDSuperAdmin).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("super-admin role is missing: run identity migration")
			}
			return err
		}

		var activeUsers int64
		if err := tx.Model(&tables.TableUser{}).Where("status = ?", tables.UserStatusActive).Count(&activeUsers).Error; err != nil {
			return err
		}
		if activeUsers != 0 {
			return ErrAlreadyExists
		}
		if err := s.CreateUser(ctx, user, tx); err != nil {
			return err
		}
		if credential != nil {
			credential.UserID = user.ID
			if err := s.CreateCredential(ctx, credential, tx); err != nil {
				return err
			}
		}
		return s.AssignRole(ctx, &tables.TableRoleAssignment{
			ID: uuid.NewString(), UserID: user.ID, RoleID: role.ID,
		}, tx)
	})
	if err != nil {
		return nil, err
	}
	return user, nil
}

// CreateCredential inserts one active verifier for a user and credential kind.
func (s *RDBConfigStore) CreateCredential(ctx context.Context, credential *tables.TableCredential, tx ...*gorm.DB) error {
	if credential == nil || strings.TrimSpace(credential.UserID) == "" || strings.TrimSpace(credential.Kind) == "" {
		return fmt.Errorf("credential user ID and kind are required")
	}
	if credential.ID == "" {
		credential.ID = uuid.NewString()
	}
	if credential.Version == 0 {
		credential.Version = 1
	}
	if err := s.identityDB(tx).WithContext(ctx).Create(credential).Error; err != nil {
		return s.parseGormError(err)
	}
	return nil
}

// GetCredentialByUserIDAndKind returns the verifier needed by a trusted
// internal password service. It must never be passed through an API DTO.
func (s *RDBConfigStore) GetCredentialByUserIDAndKind(ctx context.Context, userID, kind string) (*tables.TableCredential, error) {
	var credential tables.TableCredential
	if err := s.DB().WithContext(ctx).First(&credential, "user_id = ? AND kind = ?", userID, kind).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &credential, nil
}

// ListCredentialsByUserID supports internal lifecycle checks. Response code
// uses UserProfile instead of this persistence type.
func (s *RDBConfigStore) ListCredentialsByUserID(ctx context.Context, userID string) ([]tables.TableCredential, error) {
	var credentials []tables.TableCredential
	if err := s.DB().WithContext(ctx).Where("user_id = ?", userID).Order("created_at ASC").Find(&credentials).Error; err != nil {
		return nil, err
	}
	return credentials, nil
}

// UpgradeLocalPasswordCredential replaces a successfully verified legacy
// bcrypt credential with the current Argon2id format. The version predicate
// prevents an older login response from overwriting a newer reset.
func (s *RDBConfigStore) UpgradeLocalPasswordCredential(ctx context.Context, userID, credentialID string, expectedVersion uint64, newHash string) error {
	if strings.TrimSpace(userID) == "" || strings.TrimSpace(credentialID) == "" || expectedVersion == 0 || strings.TrimSpace(newHash) == "" {
		return ErrNotFound
	}
	return s.DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var credential tables.TableCredential
		if err := dbForUpdate(tx).Where("id = ? AND user_id = ? AND version = ? AND is_active = ?", credentialID, userID, expectedVersion, true).First(&credential).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		if credential.Kind != tables.CredentialKindPassword && credential.Kind != tables.CredentialKindLegacyPassword {
			return ErrNotFound
		}
		if credential.Kind == tables.CredentialKindLegacyPassword {
			var current tables.TableCredential
			err := dbForUpdate(tx).Where("user_id = ? AND kind = ?", userID, tables.CredentialKindPassword).First(&current).Error
			switch {
			case errors.Is(err, gorm.ErrRecordNotFound):
				if err := tx.Model(&tables.TableCredential{}).Where("id = ? AND version = ?", credential.ID, expectedVersion).Updates(map[string]any{
					"secret_hash": newHash, "version": gorm.Expr("version + ?", 1), "kind": tables.CredentialKindPassword,
				}).Error; err != nil {
					return s.parseGormError(err)
				}
			case err != nil:
				return err
			case current.IsActive:
				return ErrNotFound
			default:
				if err := tx.Model(&tables.TableCredential{}).Where("id = ? AND version = ?", current.ID, current.Version).Updates(map[string]any{
					"secret_hash": newHash, "is_active": true, "version": gorm.Expr("version + ?", 1),
				}).Error; err != nil {
					return s.parseGormError(err)
				}
				if err := tx.Model(&tables.TableCredential{}).Where("id = ? AND version = ?", credential.ID, expectedVersion).Update("is_active", false).Error; err != nil {
					return err
				}
			}
		} else if err := tx.Model(&tables.TableCredential{}).Where("id = ? AND version = ?", credential.ID, expectedVersion).Updates(map[string]any{
			"secret_hash": newHash, "version": gorm.Expr("version + ?", 1),
		}).Error; err != nil {
			return s.parseGormError(err)
		}
		return nil
	})
}

// ChangeLocalPasswordCredential atomically replaces an active verifier,
// increments AuthVersion, and revokes every active session owned by the user.
// The latter two operations ensure a stolen old session cannot survive a
// password change on another device.
func (s *RDBConfigStore) ChangeLocalPasswordCredential(ctx context.Context, userID, credentialID string, expectedVersion uint64, newHash string, changedAt time.Time) error {
	if strings.TrimSpace(userID) == "" || strings.TrimSpace(credentialID) == "" || expectedVersion == 0 || strings.TrimSpace(newHash) == "" {
		return ErrNotFound
	}
	if changedAt.IsZero() {
		changedAt = time.Now().UTC()
	}
	return s.DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var credential tables.TableCredential
		if err := dbForUpdate(tx).Where("id = ? AND user_id = ? AND version = ? AND is_active = ?", credentialID, userID, expectedVersion, true).First(&credential).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		if credential.Kind != tables.CredentialKindPassword && credential.Kind != tables.CredentialKindLegacyPassword {
			return ErrNotFound
		}
		if credential.Kind == tables.CredentialKindLegacyPassword {
			var current tables.TableCredential
			err := dbForUpdate(tx).Where("user_id = ? AND kind = ?", userID, tables.CredentialKindPassword).First(&current).Error
			switch {
			case errors.Is(err, gorm.ErrRecordNotFound):
				if err := tx.Model(&tables.TableCredential{}).Where("id = ? AND version = ?", credential.ID, expectedVersion).Updates(map[string]any{
					"secret_hash": newHash, "version": gorm.Expr("version + ?", 1), "kind": tables.CredentialKindPassword,
				}).Error; err != nil {
					return s.parseGormError(err)
				}
			case err != nil:
				return err
			case current.IsActive:
				return ErrNotFound
			default:
				if err := tx.Model(&tables.TableCredential{}).Where("id = ? AND version = ?", current.ID, current.Version).Updates(map[string]any{
					"secret_hash": newHash, "is_active": true, "version": gorm.Expr("version + ?", 1),
				}).Error; err != nil {
					return s.parseGormError(err)
				}
				if err := tx.Model(&tables.TableCredential{}).Where("id = ? AND version = ?", credential.ID, expectedVersion).Update("is_active", false).Error; err != nil {
					return err
				}
			}
		} else if err := tx.Model(&tables.TableCredential{}).Where("id = ? AND version = ?", credential.ID, expectedVersion).Updates(map[string]any{
			"secret_hash": newHash, "version": gorm.Expr("version + ?", 1),
		}).Error; err != nil {
			return s.parseGormError(err)
		}
		if result := tx.Model(&tables.TableUser{}).Where("id = ? AND status = ?", userID, tables.UserStatusActive).Update("auth_version", gorm.Expr("auth_version + ?", 1)); result.Error != nil {
			return result.Error
		} else if result.RowsAffected != 1 {
			return ErrNotFound
		}
		if err := tx.Model(&tables.SessionsTable{}).Where("user_id = ? AND revoked_at IS NULL", userID).Update("revoked_at", changedAt.UTC()).Error; err != nil {
			return err
		}
		return nil
	})
}

// CreateExternalIdentity persists a validated issuer/subject binding. The
// composite unique index prevents a provider identity from silently joining two
// users during concurrent first logins.
func (s *RDBConfigStore) CreateExternalIdentity(ctx context.Context, identity *tables.TableExternalIdentity, tx ...*gorm.DB) error {
	if identity == nil || strings.TrimSpace(identity.UserID) == "" || strings.TrimSpace(identity.ProviderID) == "" || strings.TrimSpace(identity.Issuer) == "" || strings.TrimSpace(identity.Subject) == "" {
		return fmt.Errorf("external identity user ID, provider ID, issuer, and subject are required")
	}
	if identity.ID == "" {
		identity.ID = uuid.NewString()
	}
	if err := s.identityDB(tx).WithContext(ctx).Create(identity).Error; err != nil {
		return s.parseGormError(err)
	}
	return nil
}

// GetExternalIdentityByIssuerSubject resolves a returning OIDC login after the
// provider's token has been validated.
func (s *RDBConfigStore) GetExternalIdentityByIssuerSubject(ctx context.Context, issuer, subject string) (*tables.TableExternalIdentity, error) {
	var identity tables.TableExternalIdentity
	if err := s.DB().WithContext(ctx).First(&identity, "issuer = ? AND subject = ?", strings.TrimSpace(issuer), strings.TrimSpace(subject)).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &identity, nil
}

// TouchExternalIdentity records the last successfully verified login without
// changing the issuer/subject binding. The predicate keeps a removed binding
// from being revived by a stale callback.
func (s *RDBConfigStore) TouchExternalIdentity(ctx context.Context, id string, seenAt time.Time) error {
	if strings.TrimSpace(id) == "" {
		return ErrNotFound
	}
	if seenAt.IsZero() {
		seenAt = time.Now().UTC()
	}
	result := s.DB().WithContext(ctx).Model(&tables.TableExternalIdentity{}).
		Where("id = ? AND is_active = ?", id, true).
		Update("last_seen_at", seenAt.UTC())
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return ErrNotFound
	}
	return nil
}

// SetExternalIdentityActive preserves historical provider bindings while
// preventing a disabled provider identity from authenticating.
func (s *RDBConfigStore) SetExternalIdentityActive(ctx context.Context, id string, isActive bool) error {
	result := s.DB().WithContext(ctx).Model(&tables.TableExternalIdentity{}).Where("id = ?", id).Update("is_active", isActive)
	if result.Error != nil {
		return s.parseGormError(result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// GetRole loads a bootstrap role by stable ID.
func (s *RDBConfigStore) GetRole(ctx context.Context, id string) (*tables.TableRole, error) {
	var role tables.TableRole
	if err := s.DB().WithContext(ctx).First(&role, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &role, nil
}

// AssignRole is idempotent, which lets a bootstrap retry after a response loss
// without producing duplicate grants.
func (s *RDBConfigStore) AssignRole(ctx context.Context, assignment *tables.TableRoleAssignment, tx ...*gorm.DB) error {
	if assignment == nil || assignment.UserID == "" || assignment.RoleID == "" {
		return fmt.Errorf("role assignment user ID and role ID are required")
	}
	if assignment.ID == "" {
		assignment.ID = uuid.NewString()
	}
	if err := s.identityDB(tx).WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(assignment).Error; err != nil {
		return s.parseGormError(err)
	}
	return nil
}

// GetUserRoleAssignments returns durable bootstrap assignments for later RBAC
// resolution. Role definitions are fetched separately to keep query shaping
// explicit at authorization boundaries.
func (s *RDBConfigStore) GetUserRoleAssignments(ctx context.Context, userID string) ([]tables.TableRoleAssignment, error) {
	var assignments []tables.TableRoleAssignment
	if err := s.DB().WithContext(ctx).Where("user_id = ?", userID).Order("created_at ASC").Find(&assignments).Error; err != nil {
		return nil, err
	}
	return assignments, nil
}
