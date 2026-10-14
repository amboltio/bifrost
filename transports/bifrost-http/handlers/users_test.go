package handlers

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/authorization"
	"github.com/maximhq/bifrost/framework/configstore"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
	"gorm.io/gorm"
)

type userManagementHandlerStoreStub struct {
	users          map[string]*tables.TableUser
	roles          map[string]tables.TableRole
	assignments    map[string][]string
	sessions       map[string]*tables.SessionsTable
	listRolesErr   error
	getRolesErr    error
	recoveryTokens []*tables.TableRecoveryToken
	revokedUsers   []string
	auditActions   []string
}

var _ userManagementHandlerStore = (*userManagementHandlerStoreStub)(nil)

func newUserManagementHandlerStoreStub() *userManagementHandlerStoreStub {
	viewer := tables.TableRole{ID: authorization.RoleIDViewer, Name: authorization.RoleIDViewer, DisplayName: "Viewer", Permissions: []string{string(authorization.PermissionUsersRead)}}
	superAdmin := tables.TableRole{ID: tables.RoleIDSuperAdmin, Name: tables.RoleNameSuperAdmin, DisplayName: "Super administrator", IsSystem: true, IsImmutable: true}
	return &userManagementHandlerStoreStub{
		users:       map[string]*tables.TableUser{},
		roles:       map[string]tables.TableRole{viewer.ID: viewer, superAdmin.ID: superAdmin},
		assignments: map[string][]string{"admin": {tables.RoleIDSuperAdmin}},
		sessions:    map[string]*tables.SessionsTable{},
	}
}

func (s *userManagementHandlerStoreStub) ListUsers(_ context.Context, _ configstore.UsersQueryParams) ([]tables.TableUser, int64, error) {
	users := make([]tables.TableUser, 0, len(s.users))
	for _, user := range s.users {
		users = append(users, *user)
	}
	return users, int64(len(users)), nil
}

func (s *userManagementHandlerStoreStub) ListRoles(context.Context) ([]tables.TableRole, error) {
	if s.listRolesErr != nil {
		return nil, s.listRolesErr
	}
	roles := make([]tables.TableRole, 0, len(s.roles))
	for _, role := range s.roles {
		roles = append(roles, role)
	}
	return roles, nil
}

func (s *userManagementHandlerStoreStub) GetRolesByUserID(_ context.Context, userID string) ([]tables.TableRole, error) {
	if s.getRolesErr != nil {
		return nil, s.getRolesErr
	}
	roles := make([]tables.TableRole, 0, len(s.assignments[userID]))
	for _, roleID := range s.assignments[userID] {
		roles = append(roles, s.roles[roleID])
	}
	return roles, nil
}

func (s *userManagementHandlerStoreStub) CreateManagedUser(_ context.Context, user *tables.TableUser, credential *tables.TableCredential, roleIDs []string) (*tables.TableUser, error) {
	if user.ID == "" {
		user.ID = "new-user"
	}
	if credential.SecretHash == "" {
		return nil, assert.AnError
	}
	copy := *user
	s.users[user.ID] = &copy
	s.assignments[user.ID] = append([]string(nil), roleIDs...)
	return &copy, nil
}

func (s *userManagementHandlerStoreStub) CreateManagedUserAudited(ctx context.Context, user *tables.TableUser, credential *tables.TableCredential, roleIDs []string, auditEvent *tables.TableAuditEvent, _ *tables.TableOutboxEvent) (*tables.TableUser, error) {
	s.auditActions = append(s.auditActions, auditEvent.Action)
	return s.CreateManagedUser(ctx, user, credential, roleIDs)
}

func (s *userManagementHandlerStoreStub) UpdateUserDisplayName(_ context.Context, userID, displayName string) error {
	user, exists := s.users[userID]
	if !exists {
		return configstore.ErrNotFound
	}
	user.DisplayName = displayName
	return nil
}

func (s *userManagementHandlerStoreStub) UpdateUserDisplayNameAudited(ctx context.Context, userID, displayName string, auditEvent *tables.TableAuditEvent, _ *tables.TableOutboxEvent) error {
	s.auditActions = append(s.auditActions, auditEvent.Action)
	return s.UpdateUserDisplayName(ctx, userID, displayName)
}

func (s *userManagementHandlerStoreStub) ReplaceUserRoleAssignments(_ context.Context, userID string, roleIDs []string, _ *string) error {
	if _, exists := s.users[userID]; !exists {
		return configstore.ErrNotFound
	}
	s.assignments[userID] = append([]string(nil), roleIDs...)
	return nil
}

func (s *userManagementHandlerStoreStub) ReplaceUserRoleAssignmentsAudited(ctx context.Context, userID string, roleIDs []string, assignedByUserID *string, auditEvent *tables.TableAuditEvent, _ *tables.TableOutboxEvent) error {
	s.auditActions = append(s.auditActions, auditEvent.Action)
	return s.ReplaceUserRoleAssignments(ctx, userID, roleIDs, assignedByUserID)
}

func (s *userManagementHandlerStoreStub) GetUser(_ context.Context, userID string) (*tables.TableUser, error) {
	user := s.users[userID]
	if user == nil {
		return nil, nil
	}
	copy := *user
	return &copy, nil
}

func (s *userManagementHandlerStoreStub) GetSession(_ context.Context, token string) (*tables.SessionsTable, error) {
	session := s.sessions[token]
	if session == nil {
		return nil, nil
	}
	copy := *session
	return &copy, nil
}

func (s *userManagementHandlerStoreStub) DisableUser(_ context.Context, userID string, disabledAt time.Time) error {
	user := s.users[userID]
	if user == nil {
		return configstore.ErrNotFound
	}
	user.Status = tables.UserStatusDisabled
	user.DisabledAt = &disabledAt
	s.revokedUsers = append(s.revokedUsers, userID)
	return nil
}

func (s *userManagementHandlerStoreStub) DisableUserAudited(ctx context.Context, userID string, disabledAt time.Time, auditEvent *tables.TableAuditEvent, _ *tables.TableOutboxEvent) error {
	s.auditActions = append(s.auditActions, auditEvent.Action)
	return s.DisableUser(ctx, userID, disabledAt)
}

func (s *userManagementHandlerStoreStub) RevokeAllUserSessions(_ context.Context, userID string, _ time.Time) (int64, error) {
	if s.users[userID] == nil {
		return 0, configstore.ErrNotFound
	}
	s.revokedUsers = append(s.revokedUsers, userID)
	return 2, nil
}

func (s *userManagementHandlerStoreStub) RevokeAllUserSessionsAudited(ctx context.Context, userID string, revokedAt time.Time, auditEvent *tables.TableAuditEvent, _ *tables.TableOutboxEvent) (int64, error) {
	s.auditActions = append(s.auditActions, auditEvent.Action)
	return s.RevokeAllUserSessions(ctx, userID, revokedAt)
}

func (s *userManagementHandlerStoreStub) CreateRecoveryToken(_ context.Context, token *tables.TableRecoveryToken, _ ...*gorm.DB) error {
	copy := *token
	s.recoveryTokens = append(s.recoveryTokens, &copy)
	return nil
}

func (s *userManagementHandlerStoreStub) CreateRecoveryTokenAudited(ctx context.Context, token *tables.TableRecoveryToken, auditEvent *tables.TableAuditEvent, _ *tables.TableOutboxEvent) error {
	s.auditActions = append(s.auditActions, auditEvent.Action)
	return s.CreateRecoveryToken(ctx, token)
}

func (s *userManagementHandlerStoreStub) RedeemRecoveryToken(context.Context, string, string, time.Time) (*tables.TableRecoveryToken, error) {
	return nil, configstore.ErrNotFound
}

func TestUsersHandlerCreatesListsAndResetsManagedUsers(t *testing.T) {
	store := newUserManagementHandlerStoreStub()
	handler := NewUsersHandler(store)
	require.NotNil(t, handler)

	createCtx := &fasthttp.RequestCtx{}
	createCtx.Request.Header.SetMethod(fasthttp.MethodPost)
	createCtx.Request.SetRequestURI("/api/governance/users")
	createCtx.Request.SetBodyString(`{"email":"operator@example.test","display_name":"Operator","password":"a sufficiently long password","role_ids":["viewer"]}`)
	createCtx.SetUserValue(schemas.BifrostContextKeyUserID, "admin")
	handler.createUser(createCtx)
	require.Equal(t, fasthttp.StatusCreated, createCtx.Response.StatusCode(), string(createCtx.Response.Body()))
	assert.NotContains(t, string(createCtx.Response.Body()), "a sufficiently long password")
	require.Len(t, store.users, 1)
	var created *tables.TableUser
	for _, user := range store.users {
		created = user
	}
	require.NotNil(t, created)
	assert.Equal(t, "admin", *created.CreatedByUserID)

	listCtx := &fasthttp.RequestCtx{}
	listCtx.Request.SetRequestURI("/api/governance/users")
	handler.listUsers(listCtx)
	require.Equal(t, fasthttp.StatusOK, listCtx.Response.StatusCode())
	assert.NotContains(t, string(listCtx.Response.Body()), "secret_hash")

	resetCtx := &fasthttp.RequestCtx{}
	resetCtx.Request.SetRequestURI("/api/governance/users/" + created.ID + "/reset-password")
	resetCtx.SetUserValue("id", created.ID)
	resetCtx.SetUserValue(schemas.BifrostContextKeyUserID, "admin")
	handler.resetPassword(resetCtx)
	require.Equal(t, fasthttp.StatusCreated, resetCtx.Response.StatusCode(), string(resetCtx.Response.Body()))
	var resetResponse struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(resetCtx.Response.Body(), &resetResponse))
	require.NotEmpty(t, resetResponse.Token)
	require.Len(t, store.recoveryTokens, 1)
	assert.NotEqual(t, resetResponse.Token, store.recoveryTokens[0].TokenDigest)
	assert.Equal(t, []string{"identity.user.created", "identity.user.password_reset_issued"}, store.auditActions)
}

func TestUsersHandlerRejectsShortPasswords(t *testing.T) {
	handler := NewUsersHandler(newUserManagementHandlerStoreStub())
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetRequestURI("/api/governance/users")
	ctx.Request.SetBodyString(`{"email":"operator@example.test","password":"short","role_ids":["viewer"]}`)
	ctx.SetUserValue(schemas.BifrostContextKeyAuthBypassed, true)
	handler.createUser(ctx)
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
	assert.True(t, strings.Contains(string(ctx.Response.Body()), "password"))
}

func TestUsersHandlerPreventsManagersFromAssigningSuperAdmin(t *testing.T) {
	store := newUserManagementHandlerStoreStub()
	store.roles[authorization.RoleIDUserManager] = tables.TableRole{
		ID: authorization.RoleIDUserManager, Name: authorization.RoleIDUserManager,
		Permissions: []string{string(authorization.PermissionUsersAssignRoles), string(authorization.PermissionUsersRead)}, IsSystem: true,
	}
	store.users["manager"] = &tables.TableUser{ID: "manager", Status: tables.UserStatusActive}
	store.assignments["manager"] = []string{authorization.RoleIDUserManager}
	store.users["target"] = &tables.TableUser{ID: "target", Status: tables.UserStatusActive}
	store.assignments["target"] = []string{authorization.RoleIDViewer}
	managerToken := "manager-session"
	managerID := "manager"
	store.sessions[managerToken] = &tables.SessionsTable{Token: managerToken, UserID: &managerID, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}

	handler := NewUsersHandler(store)
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodPut)
	ctx.Request.SetRequestURI("/api/governance/users/target/roles")
	ctx.Request.SetBodyString(`{"role_ids":["super_admin"]}`)
	ctx.SetUserValue("id", "target")
	ctx.SetUserValue(schemas.BifrostContextKeyUserID, "manager")
	ctx.SetUserValue(schemas.BifrostContextKeySessionToken, managerToken)

	handler.replaceRoles(ctx)

	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode(), string(ctx.Response.Body()))
	assert.Equal(t, []string{authorization.RoleIDViewer}, store.assignments["target"], "a rejected escalation must leave assignments unchanged")
	assert.Empty(t, store.auditActions, "a rejected escalation must not be audited as a successful mutation")
}

func TestUsersHandlerRequiresFreshAuthenticationToAssignSuperAdmin(t *testing.T) {
	store := newUserManagementHandlerStoreStub()
	store.users["admin"] = &tables.TableUser{ID: "admin", Status: tables.UserStatusActive}
	store.users["target"] = &tables.TableUser{ID: "target", Status: tables.UserStatusActive}
	store.assignments["target"] = []string{authorization.RoleIDViewer}
	token := "admin-session"
	adminID := "admin"
	store.sessions[token] = &tables.SessionsTable{
		Token: token, UserID: &adminID, CreatedAt: time.Now().Add(-superAdminAssignmentFreshAuthWindow - time.Second),
		ExpiresAt: time.Now().Add(time.Hour),
	}

	handler := NewUsersHandler(store)
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodPut)
	ctx.Request.SetRequestURI("/api/governance/users/target/roles")
	ctx.Request.SetBodyString(`{"role_ids":["super_admin"]}`)
	ctx.SetUserValue("id", "target")
	ctx.SetUserValue(schemas.BifrostContextKeyUserID, "admin")
	ctx.SetUserValue(schemas.BifrostContextKeySessionToken, token)

	handler.replaceRoles(ctx)

	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode(), string(ctx.Response.Body()))
	assert.Equal(t, []string{authorization.RoleIDViewer}, store.assignments["target"], "a stale session must not change assignments")
	assert.Empty(t, store.auditActions, "a stale-session denial must not record a successful mutation")
}

func TestUsersHandlerAllowsFreshSuperAdminAssignmentBySuperAdmin(t *testing.T) {
	store := newUserManagementHandlerStoreStub()
	store.users["admin"] = &tables.TableUser{ID: "admin", Status: tables.UserStatusActive}
	store.users["target"] = &tables.TableUser{ID: "target", Status: tables.UserStatusActive}
	store.assignments["target"] = []string{authorization.RoleIDViewer}
	token := "admin-session"
	adminID := "admin"
	store.sessions[token] = &tables.SessionsTable{
		Token: token, UserID: &adminID, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}

	handler := NewUsersHandler(store)
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodPut)
	ctx.Request.SetRequestURI("/api/governance/users/target/roles")
	ctx.Request.SetBodyString(`{"role_ids":["super_admin"]}`)
	ctx.SetUserValue("id", "target")
	ctx.SetUserValue(schemas.BifrostContextKeyUserID, "admin")
	ctx.SetUserValue(schemas.BifrostContextKeySessionToken, token)

	handler.replaceRoles(ctx)

	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode(), string(ctx.Response.Body()))
	assert.Equal(t, []string{tables.RoleIDSuperAdmin}, store.assignments["target"])
}

func TestUsersHandlerRejectsInvalidatedSessionForSuperAdminAssignment(t *testing.T) {
	store := newUserManagementHandlerStoreStub()
	store.users["admin"] = &tables.TableUser{ID: "admin", Status: tables.UserStatusActive, AuthVersion: 1}
	store.users["target"] = &tables.TableUser{ID: "target", Status: tables.UserStatusActive}
	store.assignments["target"] = []string{authorization.RoleIDViewer}
	token := "admin-session"
	adminID := "admin"
	store.sessions[token] = &tables.SessionsTable{
		Token: token, UserID: &adminID, AuthVersion: 0, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}

	handler := NewUsersHandler(store)
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodPut)
	ctx.Request.SetRequestURI("/api/governance/users/target/roles")
	ctx.Request.SetBodyString(`{"role_ids":["super_admin"]}`)
	ctx.SetUserValue("id", "target")
	ctx.SetUserValue(schemas.BifrostContextKeyUserID, "admin")
	ctx.SetUserValue(schemas.BifrostContextKeySessionToken, token)

	handler.replaceRoles(ctx)

	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode(), string(ctx.Response.Body()))
	assert.Equal(t, []string{authorization.RoleIDViewer}, store.assignments["target"])
	assert.Empty(t, store.auditActions)
}

func TestUsersHandlerPreventsManagersFromGrantingUndelegatedPermissions(t *testing.T) {
	store := newUserManagementHandlerStoreStub()
	store.roles[authorization.RoleIDUserManager] = tables.TableRole{
		ID: authorization.RoleIDUserManager, Name: authorization.RoleIDUserManager,
		Permissions: []string{string(authorization.PermissionUsersAssignRoles), string(authorization.PermissionUsersRead)}, IsSystem: true,
	}
	store.roles["role-editor"] = tables.TableRole{
		ID: "role-editor", Name: "role-editor", Permissions: []string{string(authorization.PermissionUsersUpdate), string(authorization.PermissionUsersAssignRoles)},
	}
	store.users["manager"] = &tables.TableUser{ID: "manager", Status: tables.UserStatusActive}
	store.assignments["manager"] = []string{authorization.RoleIDUserManager}
	store.users["target"] = &tables.TableUser{ID: "target", Status: tables.UserStatusActive}
	store.assignments["target"] = []string{authorization.RoleIDViewer}

	handler := NewUsersHandler(store)
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodPut)
	ctx.Request.SetRequestURI("/api/governance/users/target/roles")
	ctx.Request.SetBodyString(`{"role_ids":["role-editor"]}`)
	ctx.SetUserValue("id", "target")
	ctx.SetUserValue(schemas.BifrostContextKeyUserID, "manager")

	handler.replaceRoles(ctx)

	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode(), string(ctx.Response.Body()))
	assert.Equal(t, []string{authorization.RoleIDViewer}, store.assignments["target"], "a rejected escalation must leave assignments unchanged")
	assert.Empty(t, store.auditActions, "a rejected escalation must not be audited as a successful mutation")
}

func TestUsersHandlerPreventsRolePermissionEscalation(t *testing.T) {
	store := newUserManagementHandlerStoreStub()
	store.roles["role-editor"] = tables.TableRole{
		ID: "role-editor", Name: "role-editor", Permissions: []string{string(authorization.PermissionUsersUpdate), string(authorization.PermissionUsersAssignRoles)},
	}
	store.users["editor"] = &tables.TableUser{ID: "editor", Status: tables.UserStatusActive}
	store.assignments["editor"] = []string{"role-editor"}

	handler := NewUsersHandler(store)
	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue(schemas.BifrostContextKeyUserID, "editor")

	assert.False(t, handler.authorizeRoleDelegation(ctx, nil, []string{string(authorization.PermissionUsersResetPassword)}, true))
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
	assert.Empty(t, store.auditActions)
}

func TestUsersHandlerFailsClosedWhenRoleCatalogCannotBeLoadedForDelegation(t *testing.T) {
	SetLogger(&mockLogger{})
	store := newUserManagementHandlerStoreStub()
	store.roles[authorization.RoleIDUserManager] = tables.TableRole{
		ID: authorization.RoleIDUserManager, Name: authorization.RoleIDUserManager,
		Permissions: []string{string(authorization.PermissionUsersAssignRoles), string(authorization.PermissionUsersRead)}, IsSystem: true,
	}
	store.users["manager"] = &tables.TableUser{ID: "manager", Status: tables.UserStatusActive}
	store.assignments["manager"] = []string{authorization.RoleIDUserManager}
	store.users["target"] = &tables.TableUser{ID: "target", Status: tables.UserStatusActive}
	store.assignments["target"] = []string{authorization.RoleIDViewer}
	store.listRolesErr = assert.AnError

	handler := NewUsersHandler(store)
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodPut)
	ctx.Request.SetRequestURI("/api/governance/users/target/roles")
	ctx.Request.SetBodyString(`{"role_ids":["viewer"]}`)
	ctx.SetUserValue("id", "target")
	ctx.SetUserValue(schemas.BifrostContextKeyUserID, "manager")

	handler.replaceRoles(ctx)

	assert.Equal(t, fasthttp.StatusInternalServerError, ctx.Response.StatusCode())
	assert.Equal(t, []string{authorization.RoleIDViewer}, store.assignments["target"])
	assert.Empty(t, store.auditActions)
}

func TestUsersHandlerFailsClosedWhenActorRolesCannotBeLoadedForDelegation(t *testing.T) {
	SetLogger(&mockLogger{})
	store := newUserManagementHandlerStoreStub()
	store.users["manager"] = &tables.TableUser{ID: "manager", Status: tables.UserStatusActive}
	store.users["target"] = &tables.TableUser{ID: "target", Status: tables.UserStatusActive}
	store.assignments["target"] = []string{authorization.RoleIDViewer}
	store.getRolesErr = assert.AnError

	handler := NewUsersHandler(store)
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodPut)
	ctx.Request.SetRequestURI("/api/governance/users/target/roles")
	ctx.Request.SetBodyString(`{"role_ids":["viewer"]}`)
	ctx.SetUserValue("id", "target")
	ctx.SetUserValue(schemas.BifrostContextKeyUserID, "manager")

	handler.replaceRoles(ctx)

	assert.Equal(t, fasthttp.StatusInternalServerError, ctx.Response.StatusCode())
	assert.Equal(t, []string{authorization.RoleIDViewer}, store.assignments["target"])
	assert.Empty(t, store.auditActions)
}

func TestUsersHandlerRequiresRoleAssignmentPermissionWhenCreatingUser(t *testing.T) {
	store := newUserManagementHandlerStoreStub()
	store.roles["user-creator"] = tables.TableRole{
		ID: "user-creator", Name: "user-creator", Permissions: []string{string(authorization.PermissionUsersCreate)},
	}
	store.users["creator"] = &tables.TableUser{ID: "creator", Status: tables.UserStatusActive}
	store.assignments["creator"] = []string{"user-creator"}

	handler := NewUsersHandler(store)
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodPost)
	ctx.Request.SetRequestURI("/api/governance/users")
	ctx.Request.SetBodyString(`{"email":"new@example.test","display_name":"New user","password":"a sufficiently long password","role_ids":["viewer"]}`)
	ctx.SetUserValue(schemas.BifrostContextKeyUserID, "creator")

	handler.createUser(ctx)

	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode(), string(ctx.Response.Body()))
	assert.Len(t, store.users, 1, "unauthorized creation must not create the user")
	assert.Contains(t, store.users, "creator")
	assert.Empty(t, store.auditActions, "unauthorized creation must not record a successful mutation")
}

func TestUsersHandlerProtectsSuperAdminAccountsFromDelegatedManagers(t *testing.T) {
	SetLogger(&mockLogger{})
	newStore := func() *userManagementHandlerStoreStub {
		store := newUserManagementHandlerStoreStub()
		store.roles["support"] = tables.TableRole{ID: "support", Name: "support", Permissions: []string{
			string(authorization.PermissionUsersResetPassword), string(authorization.PermissionUsersRevokeSessions),
			string(authorization.PermissionUsersUpdate), string(authorization.PermissionUsersAssignRoles),
		}}
		store.users["support-user"] = &tables.TableUser{ID: "support-user", Status: tables.UserStatusActive}
		store.assignments["support-user"] = []string{"support"}
		store.users["admin"] = &tables.TableUser{ID: "admin", Status: tables.UserStatusActive}
		return store
	}
	operations := map[string]func(*UsersHandler, *fasthttp.RequestCtx){
		"reset password":  (*UsersHandler).resetPassword,
		"revoke sessions": (*UsersHandler).revokeSessions,
		"disable user":    (*UsersHandler).disableUser,
		"update user":     (*UsersHandler).updateUser,
		"replace roles":   (*UsersHandler).replaceRoles,
	}
	for name, operation := range operations {
		t.Run(name+" denied for delegated manager", func(t *testing.T) {
			store := newStore()
			handler := NewUsersHandler(store)
			ctx := &fasthttp.RequestCtx{}
			ctx.Request.Header.SetMethod(fasthttp.MethodPost)
			ctx.Request.SetBodyString(`{"display_name":"x","role_ids":["viewer"]}`)
			ctx.SetUserValue("id", "admin")
			ctx.SetUserValue(schemas.BifrostContextKeyUserID, "support-user")

			operation(handler, ctx)

			assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode(), string(ctx.Response.Body()))
			assert.Empty(t, store.recoveryTokens)
			assert.Empty(t, store.revokedUsers)
			assert.Equal(t, []string{tables.RoleIDSuperAdmin}, store.assignments["admin"])
			assert.Equal(t, tables.UserStatusActive, store.users["admin"].Status)
			assert.Empty(t, store.auditActions, "a denied operation must not be audited as a successful mutation")
		})
	}

	t.Run("fails closed when target roles cannot be loaded", func(t *testing.T) {
		store := newStore()
		store.getRolesErr = assert.AnError
		handler := NewUsersHandler(store)
		ctx := &fasthttp.RequestCtx{}
		ctx.Request.Header.SetMethod(fasthttp.MethodPost)
		ctx.SetUserValue("id", "admin")
		ctx.SetUserValue(schemas.BifrostContextKeyUserID, "support-user")

		handler.resetPassword(ctx)

		assert.Equal(t, fasthttp.StatusInternalServerError, ctx.Response.StatusCode())
		assert.Empty(t, store.recoveryTokens)
	})

	t.Run("manager may still reset a non-admin user", func(t *testing.T) {
		store := newStore()
		store.users["target"] = &tables.TableUser{ID: "target", Status: tables.UserStatusActive}
		store.assignments["target"] = []string{authorization.RoleIDViewer}
		handler := NewUsersHandler(store)
		ctx := &fasthttp.RequestCtx{}
		ctx.Request.Header.SetMethod(fasthttp.MethodPost)
		ctx.SetUserValue("id", "target")
		ctx.SetUserValue(schemas.BifrostContextKeyUserID, "support-user")

		handler.resetPassword(ctx)

		assert.Equal(t, fasthttp.StatusCreated, ctx.Response.StatusCode(), string(ctx.Response.Body()))
	})

	t.Run("super-admin actor may reset another super-admin", func(t *testing.T) {
		store := newStore()
		store.users["admin-two"] = &tables.TableUser{ID: "admin-two", Status: tables.UserStatusActive}
		store.assignments["admin-two"] = []string{tables.RoleIDSuperAdmin}
		handler := NewUsersHandler(store)
		ctx := &fasthttp.RequestCtx{}
		ctx.Request.Header.SetMethod(fasthttp.MethodPost)
		ctx.SetUserValue("id", "admin-two")
		ctx.SetUserValue(schemas.BifrostContextKeyUserID, "admin")

		handler.resetPassword(ctx)

		assert.Equal(t, fasthttp.StatusCreated, ctx.Response.StatusCode(), string(ctx.Response.Body()))
	})
}
