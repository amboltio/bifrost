package configstore

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/maximhq/bifrost/framework/authorization"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func seedUserManagementRoles(t *testing.T, store *RDBConfigStore) {
	t.Helper()
	require.NoError(t, store.DB().Where("1 = 1").Delete(&tables.TableRole{}).Error)
	for _, role := range authorization.SeededRoles() {
		require.NoError(t, store.DB().Create(&role).Error)
	}
}

func TestUserManagementStoreProtectsLastActiveSuperAdminAndRevokesSessions(t *testing.T) {
	store := setupIdentityTestStore(t, ":memory:")
	ctx := context.Background()
	seedUserManagementRoles(t, store)
	require.NoError(t, store.DB().AutoMigrate(&tables.SessionsTable{}))

	superAdmin := &tables.TableUser{ID: uuid.NewString(), Email: ptr("admin@example.test")}
	require.NoError(t, store.CreateUser(ctx, superAdmin))
	require.NoError(t, store.AssignRole(ctx, &tables.TableRoleAssignment{UserID: superAdmin.ID, RoleID: tables.RoleIDSuperAdmin}))
	require.NoError(t, store.DB().Create(&tables.SessionsTable{
		Token: "admin-session", UserID: &superAdmin.ID, AuthMethod: "local",
		ExpiresAt: time.Now().Add(time.Hour), AuthVersion: superAdmin.AuthVersion,
	}).Error)

	err := store.ReplaceUserRoleAssignments(ctx, superAdmin.ID, []string{authorization.RoleIDViewer}, nil)
	require.ErrorIs(t, err, ErrLastSuperAdmin)
	err = store.DisableUser(ctx, superAdmin.ID, time.Now())
	require.ErrorIs(t, err, ErrLastSuperAdmin)

	secondSuperAdmin := &tables.TableUser{ID: uuid.NewString(), Email: ptr("second-admin@example.test")}
	require.NoError(t, store.CreateUser(ctx, secondSuperAdmin))
	require.NoError(t, store.AssignRole(ctx, &tables.TableRoleAssignment{UserID: secondSuperAdmin.ID, RoleID: tables.RoleIDSuperAdmin}))

	require.NoError(t, store.DisableUser(ctx, superAdmin.ID, time.Now()))
	stored, err := store.GetUser(ctx, superAdmin.ID)
	require.NoError(t, err)
	assert.Equal(t, tables.UserStatusDisabled, stored.Status)
	assert.Equal(t, uint64(2), stored.AuthVersion)

	var session tables.SessionsTable
	require.NoError(t, store.DB().First(&session, "user_id = ?", superAdmin.ID).Error)
	assert.NotNil(t, session.RevokedAt)
}

func TestUserManagementStoreCreatesUsersWithKnownRolesOnly(t *testing.T) {
	store := setupIdentityTestStore(t, ":memory:")
	ctx := context.Background()
	seedUserManagementRoles(t, store)

	created, err := store.CreateManagedUser(ctx,
		&tables.TableUser{Email: ptr("operator@example.test"), DisplayName: "Operator"},
		&tables.TableCredential{SecretHash: "argon2id$test"},
		[]string{authorization.RoleIDViewer},
	)
	require.NoError(t, err)
	roles, err := store.GetRolesByUserID(ctx, created.ID)
	require.NoError(t, err)
	require.Len(t, roles, 1)
	assert.Equal(t, authorization.RoleIDViewer, roles[0].ID)

	_, err = store.CreateManagedUser(ctx,
		&tables.TableUser{Email: ptr("unknown-role@example.test")},
		&tables.TableCredential{SecretHash: "argon2id$test"},
		[]string{"does-not-exist"},
	)
	require.ErrorIs(t, err, ErrNotFound)

	var count int64
	require.NoError(t, store.DB().Model(&tables.TableUser{}).Where("normalized_email = ?", "unknown-role@example.test").Count(&count).Error)
	assert.Zero(t, count)
	assert.False(t, errors.Is(err, ErrLastSuperAdmin))
}

func TestUserManagementStoreEnforcesDelegatedRolePermissions(t *testing.T) {
	store := setupIdentityTestStore(t, ":memory:")
	ctx := context.Background()
	seedUserManagementRoles(t, store)

	manager := &tables.TableUser{ID: uuid.NewString(), Email: ptr("manager@example.test"), Status: tables.UserStatusActive}
	target := &tables.TableUser{ID: uuid.NewString(), Email: ptr("target@example.test"), Status: tables.UserStatusActive}
	require.NoError(t, store.CreateUser(ctx, manager))
	require.NoError(t, store.CreateUser(ctx, target))
	require.NoError(t, store.AssignRole(ctx, &tables.TableRoleAssignment{UserID: manager.ID, RoleID: authorization.RoleIDUserManager}))
	require.NoError(t, store.AssignRole(ctx, &tables.TableRoleAssignment{UserID: target.ID, RoleID: authorization.RoleIDViewer}))
	require.NoError(t, store.DB().Create(&tables.TableRole{
		ID: "project-admin", Name: "project-admin", DisplayName: "Project administrator",
		Permissions: []string{string(authorization.PermissionProjectsDelete)},
	}).Error)

	managerID := manager.ID
	require.NoError(t, store.ReplaceUserRoleAssignments(ctx, target.ID, []string{authorization.RoleIDViewer}, &managerID))
	permitted := &tables.TableUser{ID: uuid.NewString(), Email: ptr("permitted@example.test"), CreatedByUserID: &managerID}
	_, err := store.CreateManagedUser(ctx, permitted, &tables.TableCredential{SecretHash: "argon2id$test"}, []string{authorization.RoleIDViewer})
	require.NoError(t, err)

	audit, outbox := roleAuditFixtures()
	err = store.ReplaceUserRoleAssignmentsAudited(ctx, target.ID, []string{"project-admin"}, &managerID, audit, outbox)
	require.ErrorIs(t, err, ErrRoleDelegationDenied)
	var auditCount int64
	require.NoError(t, store.DB().Model(&tables.TableAuditEvent{}).Count(&auditCount).Error)
	assert.Zero(t, auditCount, "a denied role grant must roll back its audit event")
	roles, err := store.GetRolesByUserID(ctx, target.ID)
	require.NoError(t, err)
	require.Len(t, roles, 1)
	assert.Equal(t, authorization.RoleIDViewer, roles[0].ID)

	err = store.ReplaceUserRoleAssignments(ctx, target.ID, []string{tables.RoleIDSuperAdmin}, &managerID)
	require.ErrorIs(t, err, ErrRoleDelegationDenied)

	created := &tables.TableUser{
		ID: uuid.NewString(), Email: ptr("delegated@example.test"), CreatedByUserID: &managerID,
	}
	_, err = store.CreateManagedUser(ctx, created, &tables.TableCredential{SecretHash: "argon2id$test"}, []string{"project-admin"})
	require.ErrorIs(t, err, ErrRoleDelegationDenied)
	var count int64
	require.NoError(t, store.DB().Model(&tables.TableUser{}).Where("id = ?", created.ID).Count(&count).Error)
	assert.Zero(t, count, "rejected delegation must roll back user creation")
}

func TestAuditedUserManagementCreateWritesStateJournalAndOutboxTogether(t *testing.T) {
	store := setupIdentityTestStore(t, ":memory:")
	ctx := context.Background()
	seedUserManagementRoles(t, store)

	userID := uuid.NewString()
	created, err := store.CreateManagedUserAudited(ctx,
		&tables.TableUser{ID: userID, Email: ptr("audited@example.test"), DisplayName: "Audited"},
		&tables.TableCredential{SecretHash: "argon2id$test"},
		[]string{authorization.RoleIDViewer},
		&tables.TableAuditEvent{ActorPrincipal: "user:admin", TargetType: "user", TargetID: &userID, Action: "identity.user.created", ChangedFields: map[string]any{"role_ids": []string{authorization.RoleIDViewer}}},
		&tables.TableOutboxEvent{Topic: "identity.user.changed", DeduplicationKey: "audit-create-" + userID, Payload: map[string]any{"user_id": userID, "action": "identity.user.created"}},
	)
	require.NoError(t, err)
	assert.Equal(t, userID, created.ID)

	var users, credentials, audits, outbox int64
	require.NoError(t, store.DB().Model(&tables.TableUser{}).Count(&users).Error)
	require.NoError(t, store.DB().Model(&tables.TableCredential{}).Count(&credentials).Error)
	require.NoError(t, store.DB().Model(&tables.TableAuditEvent{}).Count(&audits).Error)
	require.NoError(t, store.DB().Model(&tables.TableOutboxEvent{}).Count(&outbox).Error)
	assert.Equal(t, int64(1), users)
	assert.Equal(t, int64(1), credentials)
	assert.Equal(t, int64(1), audits)
	assert.Equal(t, int64(1), outbox)
}

func TestUserManagementStoreSerializesParallelLastSuperAdminChanges(t *testing.T) {
	removals := map[string]func(*RDBConfigStore, context.Context, string) error{
		"disable": func(store *RDBConfigStore, ctx context.Context, userID string) error {
			return store.DisableUser(ctx, userID, time.Now())
		},
		"demote": func(store *RDBConfigStore, ctx context.Context, userID string) error {
			return store.ReplaceUserRoleAssignments(ctx, userID, []string{authorization.RoleIDViewer}, nil)
		},
	}
	for firstName, first := range removals {
		for secondName, second := range removals {
			t.Run(firstName+" and "+secondName, func(t *testing.T) {
				// A single shared-cache connection serializes SQLite writers the way
				// PostgreSQL's role row lock does, while both callers still start together.
				store := setupIdentityTestStore(t, "file:last-admin-"+firstName+"-"+secondName+"?mode=memory&cache=shared")
				sqlDB, err := store.DB().DB()
				require.NoError(t, err)
				sqlDB.SetMaxOpenConns(1)
				t.Cleanup(func() { _ = sqlDB.Close() })
				ctx := context.Background()
				seedUserManagementRoles(t, store)
				require.NoError(t, store.DB().AutoMigrate(&tables.SessionsTable{}))

				admins := make([]*tables.TableUser, 2)
				for i := range admins {
					admins[i] = &tables.TableUser{ID: uuid.NewString(), Email: ptr(uuid.NewString() + "@example.test")}
					require.NoError(t, store.CreateUser(ctx, admins[i]))
					require.NoError(t, store.AssignRole(ctx, &tables.TableRoleAssignment{UserID: admins[i].ID, RoleID: tables.RoleIDSuperAdmin}))
				}

				start := make(chan struct{})
				errs := make(chan error, 2)
				var group sync.WaitGroup
				for i, remove := range []func(*RDBConfigStore, context.Context, string) error{first, second} {
					group.Add(1)
					go func() {
						defer group.Done()
						<-start
						errs <- remove(store, ctx, admins[i].ID)
					}()
				}
				close(start)
				group.Wait()
				close(errs)

				var succeeded, protected int
				for err := range errs {
					switch {
					case err == nil:
						succeeded++
					case errors.Is(err, ErrLastSuperAdmin):
						protected++
					default:
						t.Fatalf("unexpected concurrent super-admin removal error: %v", err)
					}
				}
				assert.Equal(t, 1, succeeded)
				assert.Equal(t, 1, protected)

				var remaining int64
				require.NoError(t, store.DB().Model(&tables.TableUser{}).
					Joins("JOIN identity_role_assignments ON identity_role_assignments.user_id = identity_users.id").
					Where("identity_users.status = ? AND identity_role_assignments.role_id = ?", tables.UserStatusActive, tables.RoleIDSuperAdmin).
					Count(&remaining).Error)
				assert.Equal(t, int64(1), remaining, "exactly one active super-admin must survive")
			})
		}
	}
}
