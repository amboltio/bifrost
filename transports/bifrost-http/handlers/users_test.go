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
	recoveryTokens []*tables.TableRecoveryToken
	revokedUsers   []string
}

func newUserManagementHandlerStoreStub() *userManagementHandlerStoreStub {
	viewer := tables.TableRole{ID: authorization.RoleIDViewer, Name: authorization.RoleIDViewer, DisplayName: "Viewer", Permissions: []string{string(authorization.PermissionUsersRead)}}
	return &userManagementHandlerStoreStub{
		users:       map[string]*tables.TableUser{},
		roles:       map[string]tables.TableRole{viewer.ID: viewer},
		assignments: map[string][]string{},
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
	roles := make([]tables.TableRole, 0, len(s.roles))
	for _, role := range s.roles {
		roles = append(roles, role)
	}
	return roles, nil
}

func (s *userManagementHandlerStoreStub) GetRolesByUserID(_ context.Context, userID string) ([]tables.TableRole, error) {
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

func (s *userManagementHandlerStoreStub) UpdateUserDisplayName(_ context.Context, userID, displayName string) error {
	user, exists := s.users[userID]
	if !exists {
		return configstore.ErrNotFound
	}
	user.DisplayName = displayName
	return nil
}

func (s *userManagementHandlerStoreStub) ReplaceUserRoleAssignments(_ context.Context, userID string, roleIDs []string, _ *string) error {
	if _, exists := s.users[userID]; !exists {
		return configstore.ErrNotFound
	}
	s.assignments[userID] = append([]string(nil), roleIDs...)
	return nil
}

func (s *userManagementHandlerStoreStub) GetUser(_ context.Context, userID string) (*tables.TableUser, error) {
	user := s.users[userID]
	if user == nil {
		return nil, nil
	}
	copy := *user
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

func (s *userManagementHandlerStoreStub) RevokeAllUserSessions(_ context.Context, userID string, _ time.Time) (int64, error) {
	if s.users[userID] == nil {
		return 0, configstore.ErrNotFound
	}
	s.revokedUsers = append(s.revokedUsers, userID)
	return 2, nil
}

func (s *userManagementHandlerStoreStub) CreateRecoveryToken(_ context.Context, token *tables.TableRecoveryToken, _ ...*gorm.DB) error {
	copy := *token
	s.recoveryTokens = append(s.recoveryTokens, &copy)
	return nil
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
	created := store.users["new-user"]
	require.NotNil(t, created)
	assert.Equal(t, "admin", *created.CreatedByUserID)

	listCtx := &fasthttp.RequestCtx{}
	listCtx.Request.SetRequestURI("/api/governance/users")
	handler.listUsers(listCtx)
	require.Equal(t, fasthttp.StatusOK, listCtx.Response.StatusCode())
	assert.NotContains(t, string(listCtx.Response.Body()), "secret_hash")

	resetCtx := &fasthttp.RequestCtx{}
	resetCtx.Request.SetRequestURI("/api/governance/users/new-user/reset-password")
	resetCtx.SetUserValue("id", "new-user")
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
}

func TestUsersHandlerRejectsShortPasswords(t *testing.T) {
	handler := NewUsersHandler(newUserManagementHandlerStoreStub())
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetRequestURI("/api/governance/users")
	ctx.Request.SetBodyString(`{"email":"operator@example.test","password":"short","role_ids":["viewer"]}`)
	handler.createUser(ctx)
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
	assert.True(t, strings.Contains(string(ctx.Response.Body()), "password"))
}
