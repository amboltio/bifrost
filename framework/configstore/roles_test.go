package configstore

import (
	"context"
	"errors"
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
