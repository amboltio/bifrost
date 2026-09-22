package configstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/maximhq/bifrost/framework/authorization"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"gorm.io/gorm"
)

// RoleManagementStore is the audited role-catalog contract used by the
// governance API. System roles are seeded by migrations and cannot be edited
// or deleted through this surface.
type RoleManagementStore interface {
	GetRole(ctx context.Context, id string) (*tables.TableRole, error)
	CreateRoleAudited(ctx context.Context, role *tables.TableRole, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) (*tables.TableRole, error)
	UpdateRoleAudited(ctx context.Context, id, displayName string, permissions []string, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) (*tables.TableRole, error)
	DeleteRoleAudited(ctx context.Context, id string, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) error
}

// UsersQueryParams bounds canonical-user search and pagination at the store
// boundary. Handler authorization determines which rows are visible.
type UsersQueryParams struct {
	Search string
	Limit  int
	Offset int
}

// UserManagementStore is the focused persistence contract for protected user
// administration. It remains separate from ConfigStore while this first RBAC
// slice is introduced, avoiding a large mock churn in unrelated packages.
type UserManagementStore interface {
	ListUsers(ctx context.Context, params UsersQueryParams) ([]tables.TableUser, int64, error)
	ListRoles(ctx context.Context) ([]tables.TableRole, error)
	GetRolesByUserID(ctx context.Context, userID string) ([]tables.TableRole, error)
	CreateManagedUser(ctx context.Context, user *tables.TableUser, credential *tables.TableCredential, roleIDs []string) (*tables.TableUser, error)
	UpdateUserDisplayName(ctx context.Context, userID, displayName string) error
	ReplaceUserRoleAssignments(ctx context.Context, userID string, roleIDs []string, assignedByUserID *string) error
}

// AuditedUserManagementStore makes privileged identity mutations durable
// together with their immutable journal and invalidation event. The handler
// uses this stricter contract rather than accepting a successful user change
// that cannot be audited.
type AuditedUserManagementStore interface {
	UserManagementStore
	CreateManagedUserAudited(ctx context.Context, user *tables.TableUser, credential *tables.TableCredential, roleIDs []string, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) (*tables.TableUser, error)
	UpdateUserDisplayNameAudited(ctx context.Context, userID, displayName string, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) error
	ReplaceUserRoleAssignmentsAudited(ctx context.Context, userID string, roleIDs []string, assignedByUserID *string, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) error
	DisableUserAudited(ctx context.Context, userID string, disabledAt time.Time, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) error
	RevokeAllUserSessionsAudited(ctx context.Context, userID string, revokedAt time.Time, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) (int64, error)
}

// ListUsers returns a bounded administration page. Identity rows have no
// credentials joined, so callers cannot accidentally return verifier data.
func (s *RDBConfigStore) ListUsers(ctx context.Context, params UsersQueryParams) ([]tables.TableUser, int64, error) {
	limit := params.Limit
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	offset := max(params.Offset, 0)
	query := s.DB().WithContext(ctx).Model(&tables.TableUser{})
	if search := strings.TrimSpace(params.Search); search != "" {
		needle := "%" + strings.ToLower(search) + "%"
		query = query.Where("LOWER(COALESCE(email, '')) LIKE ? OR LOWER(display_name) LIKE ? OR LOWER(COALESCE(legacy_username, '')) LIKE ?", needle, needle, needle)
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var users []tables.TableUser
	if err := query.Order("created_at DESC, id DESC").Limit(limit).Offset(offset).Find(&users).Error; err != nil {
		return nil, 0, err
	}
	return users, total, nil
}

// ListRoles returns persisted role definitions including their typed
// permissions, which are safe to show in a management response.
func (s *RDBConfigStore) ListRoles(ctx context.Context) ([]tables.TableRole, error) {
	var roles []tables.TableRole
	if err := s.DB().WithContext(ctx).Order("name ASC").Find(&roles).Error; err != nil {
		return nil, err
	}
	return roles, nil
}

// CreateRoleAudited creates a mutable, non-system role and records the
// administrator action in the same transaction as the catalog row.
func (s *RDBConfigStore) CreateRoleAudited(ctx context.Context, role *tables.TableRole, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) (*tables.TableRole, error) {
	if role == nil {
		return nil, fmt.Errorf("role is required")
	}
	role.ID = strings.TrimSpace(role.ID)
	if role.ID == "" {
		role.ID = uuid.NewString()
	}
	role.Name = strings.TrimSpace(role.Name)
	role.DisplayName = strings.TrimSpace(role.DisplayName)
	if role.Name == "" || role.DisplayName == "" {
		return nil, fmt.Errorf("role name and display name are required")
	}
	permissions, err := normalizeRolePermissions(role.Permissions)
	if err != nil {
		return nil, err
	}
	role.Permissions = permissions
	role.IsSystem = false
	role.IsImmutable = false
	err = s.ApplyAuditedChange(ctx, auditEvent, outboxEvent, func(tx *gorm.DB) error {
		if err := tx.WithContext(ctx).Create(role).Error; err != nil {
			return s.parseGormError(err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return role, nil
}

// UpdateRoleAudited updates only mutable role fields. Permissions are checked
// against the published permission catalog before the transaction begins.
func (s *RDBConfigStore) UpdateRoleAudited(ctx context.Context, id, displayName string, permissions []string, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) (*tables.TableRole, error) {
	id = strings.TrimSpace(id)
	displayName = strings.TrimSpace(displayName)
	if id == "" || displayName == "" {
		return nil, ErrNotFound
	}
	permissions, err := normalizeRolePermissions(permissions)
	if err != nil {
		return nil, err
	}
	var role tables.TableRole
	permissionsJSON, err := json.Marshal(permissions)
	if err != nil {
		return nil, err
	}
	err = s.ApplyAuditedChange(ctx, auditEvent, outboxEvent, func(tx *gorm.DB) error {
		if err := dbForUpdate(tx).First(&role, "id = ?", id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		if role.IsSystem || role.IsImmutable {
			return ErrRoleImmutable
		}
		if err := tx.WithContext(ctx).Model(&tables.TableRole{}).Where("id = ?", id).Updates(map[string]any{"display_name": displayName, "permissions": string(permissionsJSON), "updated_at": time.Now().UTC()}).Error; err != nil {
			return s.parseGormError(err)
		}
		role.DisplayName, role.Permissions = displayName, permissions
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &role, nil
}

// DeleteRoleAudited removes a mutable role after ensuring no user still
// depends on it. Keeping this invariant explicit avoids dangling grants.
func (s *RDBConfigStore) DeleteRoleAudited(ctx context.Context, id string, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return ErrNotFound
	}
	return s.ApplyAuditedChange(ctx, auditEvent, outboxEvent, func(tx *gorm.DB) error {
		var role tables.TableRole
		if err := dbForUpdate(tx).First(&role, "id = ?", id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		if role.IsSystem || role.IsImmutable {
			return ErrRoleImmutable
		}
		var assignments int64
		if err := tx.Model(&tables.TableRoleAssignment{}).Where("role_id = ?", id).Count(&assignments).Error; err != nil {
			return err
		}
		if assignments > 0 {
			return ErrRoleInUse
		}
		return tx.Delete(&role).Error
	})
}

func normalizeRolePermissions(permissions []string) ([]string, error) {
	allowed := make(map[string]struct{}, len(authorization.Catalog()))
	for _, permission := range authorization.Catalog() {
		allowed[string(permission)] = struct{}{}
	}
	result := make([]string, 0, len(permissions))
	seen := make(map[string]struct{}, len(permissions))
	for _, permission := range permissions {
		permission = strings.TrimSpace(permission)
		if permission == "" {
			continue
		}
		if _, ok := allowed[permission]; !ok {
			return nil, fmt.Errorf("%w: %s", ErrInvalidPermission, permission)
		}
		if _, ok := seen[permission]; ok {
			continue
		}
		seen[permission] = struct{}{}
		result = append(result, permission)
	}
	slices.Sort(result)
	return result, nil
}

// GetRolesByUserID resolves only currently assigned roles. Broken assignment
// rows cannot grant an implicit permission because the join requires a role.
func (s *RDBConfigStore) GetRolesByUserID(ctx context.Context, userID string) ([]tables.TableRole, error) {
	if strings.TrimSpace(userID) == "" {
		return []tables.TableRole{}, nil
	}
	var roles []tables.TableRole
	err := s.DB().WithContext(ctx).Model(&tables.TableRole{}).
		Joins("JOIN identity_role_assignments ON identity_role_assignments.role_id = identity_roles.id").
		Where("identity_role_assignments.user_id = ?", userID).
		Order("identity_roles.name ASC").
		Find(&roles).Error
	if err != nil {
		return nil, err
	}
	return roles, nil
}

// CreateManagedUser atomically creates a canonical user, one current password
// verifier, and its role assignments. PasswordHash must already be a bounded
// verifier produced by identity.PasswordService.
func (s *RDBConfigStore) CreateManagedUser(ctx context.Context, user *tables.TableUser, credential *tables.TableCredential, roleIDs []string) (*tables.TableUser, error) {
	if user == nil || credential == nil || strings.TrimSpace(credential.SecretHash) == "" {
		return nil, fmt.Errorf("user and password credential are required")
	}
	roleIDs = normalizedRoleIDs(roleIDs)
	if len(roleIDs) == 0 {
		return nil, fmt.Errorf("at least one role is required")
	}
	if user.ID == "" {
		user.ID = uuid.NewString()
	}
	err := s.DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return s.createManagedUser(ctx, tx, user, credential, roleIDs)
	})
	if err != nil {
		return nil, err
	}
	return user, nil
}

// CreateManagedUserAudited applies creation, the security journal entry, and
// cache/session invalidation notification in one transaction.
func (s *RDBConfigStore) CreateManagedUserAudited(ctx context.Context, user *tables.TableUser, credential *tables.TableCredential, roleIDs []string, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) (*tables.TableUser, error) {
	if user == nil || credential == nil || strings.TrimSpace(credential.SecretHash) == "" {
		return nil, fmt.Errorf("user and password credential are required")
	}
	roleIDs = normalizedRoleIDs(roleIDs)
	if len(roleIDs) == 0 {
		return nil, fmt.Errorf("at least one role is required")
	}
	if user.ID == "" {
		user.ID = uuid.NewString()
	}
	err := s.ApplyAuditedChange(ctx, auditEvent, outboxEvent, func(tx *gorm.DB) error {
		return s.createManagedUser(ctx, tx, user, credential, roleIDs)
	})
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (s *RDBConfigStore) createManagedUser(ctx context.Context, tx *gorm.DB, user *tables.TableUser, credential *tables.TableCredential, roleIDs []string) error {
	if err := requireKnownRoles(tx, roleIDs); err != nil {
		return err
	}
	if err := s.CreateUser(ctx, user, tx); err != nil {
		return err
	}
	credential.ID = uuid.NewString()
	credential.UserID = user.ID
	credential.Kind = tables.CredentialKindPassword
	credential.Version = 1
	credential.IsActive = true
	if err := s.CreateCredential(ctx, credential, tx); err != nil {
		return err
	}
	for _, roleID := range roleIDs {
		if err := s.AssignRole(ctx, &tables.TableRoleAssignment{ID: uuid.NewString(), UserID: user.ID, RoleID: roleID, AssignedByUserID: user.CreatedByUserID}, tx); err != nil {
			return err
		}
	}
	return nil
}

// UpdateUserDisplayName changes only a non-sensitive profile field. Email
// changes and credential replacement are separate operations with their own
// verification policies.
func (s *RDBConfigStore) UpdateUserDisplayName(ctx context.Context, userID, displayName string) error {
	if strings.TrimSpace(userID) == "" {
		return ErrNotFound
	}
	return s.updateUserDisplayName(ctx, s.DB(), userID, displayName)
}

// UpdateUserDisplayNameAudited changes a profile field together with its
// journal entry so later investigations can distinguish administrative edits.
func (s *RDBConfigStore) UpdateUserDisplayNameAudited(ctx context.Context, userID, displayName string, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) error {
	if strings.TrimSpace(userID) == "" {
		return ErrNotFound
	}
	return s.ApplyAuditedChange(ctx, auditEvent, outboxEvent, func(tx *gorm.DB) error {
		return s.updateUserDisplayName(ctx, tx, userID, displayName)
	})
}

func (s *RDBConfigStore) updateUserDisplayName(ctx context.Context, db *gorm.DB, userID, displayName string) error {
	result := db.WithContext(ctx).Model(&tables.TableUser{}).Where("id = ?", userID).Update("display_name", strings.TrimSpace(displayName))
	if result.Error != nil {
		return s.parseGormError(result.Error)
	}
	if result.RowsAffected != 1 {
		return ErrNotFound
	}
	return nil
}

// ReplaceUserRoleAssignments applies an exact role set under the super-admin
// serialization lock. Removing the final active super-admin is rejected in
// the same transaction as the deletion.
func (s *RDBConfigStore) ReplaceUserRoleAssignments(ctx context.Context, userID string, roleIDs []string, assignedByUserID *string) error {
	if strings.TrimSpace(userID) == "" {
		return ErrNotFound
	}
	roleIDs = normalizedRoleIDs(roleIDs)
	if len(roleIDs) == 0 {
		return fmt.Errorf("at least one role is required")
	}
	return s.DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return s.replaceUserRoleAssignments(tx, userID, roleIDs, assignedByUserID)
	})
}

// ReplaceUserRoleAssignmentsAudited atomically records a complete role-set
// replacement beside the protected super-admin invariant check.
func (s *RDBConfigStore) ReplaceUserRoleAssignmentsAudited(ctx context.Context, userID string, roleIDs []string, assignedByUserID *string, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) error {
	if strings.TrimSpace(userID) == "" {
		return ErrNotFound
	}
	roleIDs = normalizedRoleIDs(roleIDs)
	if len(roleIDs) == 0 {
		return fmt.Errorf("at least one role is required")
	}
	return s.ApplyAuditedChange(ctx, auditEvent, outboxEvent, func(tx *gorm.DB) error {
		return s.replaceUserRoleAssignments(tx, userID, roleIDs, assignedByUserID)
	})
}

func (s *RDBConfigStore) replaceUserRoleAssignments(tx *gorm.DB, userID string, roleIDs []string, assignedByUserID *string) error {
	user, err := lockedUser(tx, userID)
	if err != nil {
		return err
	}
	if err := lockSuperAdminRole(tx); err != nil {
		return err
	}
	if err := requireKnownRoles(tx, roleIDs); err != nil {
		return err
	}
	var current []tables.TableRoleAssignment
	if err := tx.Where("user_id = ?", userID).Find(&current).Error; err != nil {
		return err
	}
	currentHasSuperAdmin := slices.ContainsFunc(current, func(assignment tables.TableRoleAssignment) bool { return assignment.RoleID == tables.RoleIDSuperAdmin })
	wantedSuperAdmin := slices.Contains(roleIDs, tables.RoleIDSuperAdmin)
	if user.Status == tables.UserStatusActive && currentHasSuperAdmin && !wantedSuperAdmin {
		if err := requireAnotherActiveSuperAdmin(tx); err != nil {
			return err
		}
	}
	if err := tx.Where("user_id = ?", userID).Delete(&tables.TableRoleAssignment{}).Error; err != nil {
		return err
	}
	for _, roleID := range roleIDs {
		if err := tx.Create(&tables.TableRoleAssignment{ID: uuid.NewString(), UserID: userID, RoleID: roleID, AssignedByUserID: assignedByUserID}).Error; err != nil {
			return s.parseGormError(err)
		}
	}
	return nil
}

func normalizedRoleIDs(roleIDs []string) []string {
	result := make([]string, 0, len(roleIDs))
	seen := make(map[string]struct{}, len(roleIDs))
	for _, roleID := range roleIDs {
		roleID = strings.TrimSpace(roleID)
		if roleID == "" {
			continue
		}
		if _, exists := seen[roleID]; exists {
			continue
		}
		seen[roleID] = struct{}{}
		result = append(result, roleID)
	}
	return result
}

func requireKnownRoles(tx *gorm.DB, roleIDs []string) error {
	var count int64
	if err := tx.Model(&tables.TableRole{}).Where("id IN ?", roleIDs).Count(&count).Error; err != nil {
		return err
	}
	if count != int64(len(roleIDs)) {
		return ErrNotFound
	}
	return nil
}

func lockedUser(tx *gorm.DB, userID string) (*tables.TableUser, error) {
	var user tables.TableUser
	if err := dbForUpdate(tx).First(&user, "id = ?", userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &user, nil
}

func lockSuperAdminRole(tx *gorm.DB) error {
	var role tables.TableRole
	if err := dbForUpdate(tx).First(&role, "id = ?", tables.RoleIDSuperAdmin).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("super-admin role is missing")
		}
		return err
	}
	return nil
}

func requireAnotherActiveSuperAdmin(tx *gorm.DB) error {
	var count int64
	err := tx.Model(&tables.TableUser{}).
		Joins("JOIN identity_role_assignments ON identity_role_assignments.user_id = identity_users.id").
		Where("identity_users.status = ? AND identity_role_assignments.role_id = ?", tables.UserStatusActive, tables.RoleIDSuperAdmin).
		Count(&count).Error
	if err != nil {
		return err
	}
	if count <= 1 {
		return ErrLastSuperAdmin
	}
	return nil
}

// RevokeAllUserSessions is available to privileged management endpoints and
// retains session history for audit instead of deleting credential rows.
func (s *RDBConfigStore) RevokeAllUserSessions(ctx context.Context, userID string, revokedAt time.Time) (int64, error) {
	return s.revokeAllUserSessions(ctx, s.DB(), userID, revokedAt)
}

// RevokeAllUserSessionsAudited records an operator-directed global logout in
// the same transaction as session revocation.
func (s *RDBConfigStore) RevokeAllUserSessionsAudited(ctx context.Context, userID string, revokedAt time.Time, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) (int64, error) {
	var revoked int64
	err := s.ApplyAuditedChange(ctx, auditEvent, outboxEvent, func(tx *gorm.DB) error {
		var err error
		revoked, err = s.revokeAllUserSessions(ctx, tx, userID, revokedAt)
		return err
	})
	return revoked, err
}

func (s *RDBConfigStore) revokeAllUserSessions(ctx context.Context, db *gorm.DB, userID string, revokedAt time.Time) (int64, error) {
	if strings.TrimSpace(userID) == "" {
		return 0, ErrNotFound
	}
	result := db.WithContext(ctx).Model(&tables.SessionsTable{}).
		Where("user_id = ? AND revoked_at IS NULL", userID).
		Update("revoked_at", revokedAt.UTC())
	return result.RowsAffected, result.Error
}
