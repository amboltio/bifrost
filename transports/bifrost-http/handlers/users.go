package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"github.com/fasthttp/router"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/configstore"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/maximhq/bifrost/framework/identity"
	"github.com/maximhq/bifrost/transports/bifrost-http/lib"
	"github.com/valyala/fasthttp"
)

// userManagementHandlerStore combines only the identity operations used by
// the protected user-administration API. It deliberately avoids expanding the
// broad ConfigStore interface and keeps transport tests independent of its
// unrelated persistence methods.
type userManagementHandlerStore interface {
	configstore.UserManagementStore
	configstore.RecoveryTokenStore
	GetUser(ctx context.Context, id string) (*tables.TableUser, error)
	DisableUser(ctx context.Context, id string, disabledAt time.Time) error
	RevokeAllUserSessions(ctx context.Context, userID string, revokedAt time.Time) (int64, error)
}

// UsersHandler manages canonical users, role grants, and administrator-issued
// reset tokens. Its routes rely on IdentityAuthorizationMiddleware for the
// resource-specific permission check and keep a small store contract for
// direct handler tests.
type UsersHandler struct {
	store     userManagementHandlerStore
	passwords *identity.PasswordService
	recovery  *identity.RecoveryService
	now       func() time.Time
}

type managedRoleResponse struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	DisplayName string   `json:"display_name"`
	Permissions []string `json:"permissions"`
	IsSystem    bool     `json:"is_system"`
	IsImmutable bool     `json:"is_immutable"`
}

type managedUserResponse struct {
	configstore.UserProfile
	Roles []managedRoleResponse `json:"roles"`
}

// NewUsersHandler returns nil when persistence does not implement the
// canonical identity contracts. That keeps deployments using a reduced custom
// config store bootable while ensuring no partial user API is registered.
func NewUsersHandler(store any) *UsersHandler {
	managementStore, ok := store.(userManagementHandlerStore)
	if !ok || managementStore == nil {
		return nil
	}
	passwords := identity.NewPasswordService()
	return &UsersHandler{
		store: managementStore, passwords: passwords,
		recovery: identity.NewRecoveryService(managementStore, passwords, nil), now: time.Now,
	}
}

// RegisterRoutes installs the user administration surface below governance so
// it follows the dashboard's established management route namespace.
func (h *UsersHandler) RegisterRoutes(r *router.Router, middlewares ...schemas.BifrostHTTPMiddleware) {
	r.GET("/api/governance/users", lib.ChainMiddlewares(h.listUsers, middlewares...))
	r.POST("/api/governance/users", lib.ChainMiddlewares(h.createUser, middlewares...))
	r.GET("/api/governance/roles", lib.ChainMiddlewares(h.listRoles, middlewares...))
	r.GET("/api/governance/users/{id}", lib.ChainMiddlewares(h.getUser, middlewares...))
	r.PATCH("/api/governance/users/{id}", lib.ChainMiddlewares(h.updateUser, middlewares...))
	r.PUT("/api/governance/users/{id}", lib.ChainMiddlewares(h.updateUser, middlewares...))
	r.DELETE("/api/governance/users/{id}", lib.ChainMiddlewares(h.disableUser, middlewares...))
	r.POST("/api/governance/users/{id}/reset-password", lib.ChainMiddlewares(h.resetPassword, middlewares...))
	r.POST("/api/governance/users/{id}/revoke-sessions", lib.ChainMiddlewares(h.revokeSessions, middlewares...))
	r.PUT("/api/governance/users/{id}/roles", lib.ChainMiddlewares(h.replaceRoles, middlewares...))
}

func (h *UsersHandler) listUsers(ctx *fasthttp.RequestCtx) {
	params, ok := usersQueryParams(ctx)
	if !ok {
		SendError(ctx, fasthttp.StatusBadRequest, "limit and offset must be non-negative integers")
		return
	}
	users, total, err := h.store.ListUsers(ctx, params)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to list users")
		return
	}
	response := make([]managedUserResponse, 0, len(users))
	for _, user := range users {
		view, err := h.userResponse(ctx, user)
		if err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, "Failed to resolve user roles")
			return
		}
		response = append(response, view)
	}
	SendJSON(ctx, map[string]any{
		"users": response, "total": total, "limit": params.Limit, "offset": params.Offset,
	})
}

func (h *UsersHandler) listRoles(ctx *fasthttp.RequestCtx) {
	roles, err := h.store.ListRoles(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to list roles")
		return
	}
	response := make([]managedRoleResponse, 0, len(roles))
	for _, role := range roles {
		response = append(response, newManagedRoleResponse(role))
	}
	SendJSON(ctx, map[string]any{"roles": response})
}

func (h *UsersHandler) getUser(ctx *fasthttp.RequestCtx) {
	user, ok := h.requiredUser(ctx)
	if !ok {
		return
	}
	response, err := h.userResponse(ctx, *user)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to resolve user roles")
		return
	}
	SendJSON(ctx, response)
}

func (h *UsersHandler) createUser(ctx *fasthttp.RequestCtx) {
	if !allowSessionStateChange(ctx) {
		SendError(ctx, fasthttp.StatusForbidden, "Invalid request origin")
		return
	}
	request := struct {
		Email       string   `json:"email"`
		DisplayName string   `json:"display_name"`
		Password    string   `json:"password"`
		RoleIDs     []string `json:"role_ids"`
	}{}
	if err := json.Unmarshal(ctx.PostBody(), &request); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid request payload")
		return
	}
	email, ok := validManagedUserEmail(request.Email)
	if !ok {
		SendError(ctx, fasthttp.StatusBadRequest, "A valid email address is required")
		return
	}
	passwordHash, err := h.passwords.Hash(request.Password)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}
	actorID := canonicalActorUserID(ctx)
	user := &tables.TableUser{
		Email: &email, DisplayName: strings.TrimSpace(request.DisplayName), Status: tables.UserStatusActive,
		CreatedByUserID: actorID,
	}
	created, err := h.store.CreateManagedUser(ctx, user, &tables.TableCredential{SecretHash: passwordHash}, request.RoleIDs)
	if h.writeStoreError(ctx, err) {
		return
	}
	response, err := h.userResponse(ctx, *created)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "User was created but roles could not be resolved")
		return
	}
	SendJSONWithStatus(ctx, response, fasthttp.StatusCreated)
}

func (h *UsersHandler) updateUser(ctx *fasthttp.RequestCtx) {
	if !allowSessionStateChange(ctx) {
		SendError(ctx, fasthttp.StatusForbidden, "Invalid request origin")
		return
	}
	user, ok := h.requiredUser(ctx)
	if !ok {
		return
	}
	request := struct {
		DisplayName *string `json:"display_name"`
	}{}
	if err := json.Unmarshal(ctx.PostBody(), &request); err != nil || request.DisplayName == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "display_name is required")
		return
	}
	if err := h.store.UpdateUserDisplayName(ctx, user.ID, strings.TrimSpace(*request.DisplayName)); h.writeStoreError(ctx, err) {
		return
	}
	user.DisplayName = strings.TrimSpace(*request.DisplayName)
	response, err := h.userResponse(ctx, *user)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to resolve user roles")
		return
	}
	SendJSON(ctx, response)
}

func (h *UsersHandler) disableUser(ctx *fasthttp.RequestCtx) {
	if !allowSessionStateChange(ctx) {
		SendError(ctx, fasthttp.StatusForbidden, "Invalid request origin")
		return
	}
	user, ok := h.requiredUser(ctx)
	if !ok {
		return
	}
	if err := h.store.DisableUser(ctx, user.ID, h.now().UTC()); h.writeStoreError(ctx, err) {
		return
	}
	ctx.SetStatusCode(fasthttp.StatusNoContent)
}

func (h *UsersHandler) resetPassword(ctx *fasthttp.RequestCtx) {
	if !allowSessionStateChange(ctx) {
		SendError(ctx, fasthttp.StatusForbidden, "Invalid request origin")
		return
	}
	user, ok := h.requiredUser(ctx)
	if !ok {
		return
	}
	if user.Status != tables.UserStatusActive {
		SendError(ctx, fasthttp.StatusConflict, "Password reset requires an active user")
		return
	}
	rawToken, expiresAt, err := h.recovery.Issue(ctx, user.ID, tables.RecoveryTokenPurposeReset, canonicalActorUserID(ctx))
	if h.writeStoreError(ctx, err) {
		return
	}
	// The plaintext token exists only in this response. The persistence layer
	// stores its SHA-256 digest and never includes it in user DTOs or audit data.
	SendJSONWithStatus(ctx, map[string]any{"token": rawToken, "expires_at": expiresAt}, fasthttp.StatusCreated)
}

func (h *UsersHandler) revokeSessions(ctx *fasthttp.RequestCtx) {
	if !allowSessionStateChange(ctx) {
		SendError(ctx, fasthttp.StatusForbidden, "Invalid request origin")
		return
	}
	user, ok := h.requiredUser(ctx)
	if !ok {
		return
	}
	revoked, err := h.store.RevokeAllUserSessions(ctx, user.ID, h.now().UTC())
	if h.writeStoreError(ctx, err) {
		return
	}
	SendJSON(ctx, map[string]any{"revoked_sessions": revoked})
}

func (h *UsersHandler) replaceRoles(ctx *fasthttp.RequestCtx) {
	if !allowSessionStateChange(ctx) {
		SendError(ctx, fasthttp.StatusForbidden, "Invalid request origin")
		return
	}
	user, ok := h.requiredUser(ctx)
	if !ok {
		return
	}
	request := struct {
		RoleIDs []string `json:"role_ids"`
	}{}
	if err := json.Unmarshal(ctx.PostBody(), &request); err != nil || len(request.RoleIDs) == 0 {
		SendError(ctx, fasthttp.StatusBadRequest, "role_ids is required")
		return
	}
	if err := h.store.ReplaceUserRoleAssignments(ctx, user.ID, request.RoleIDs, canonicalActorUserID(ctx)); h.writeStoreError(ctx, err) {
		return
	}
	response, err := h.userResponse(ctx, *user)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Roles were updated but could not be resolved")
		return
	}
	SendJSON(ctx, response)
}

func (h *UsersHandler) requiredUser(ctx *fasthttp.RequestCtx) (*tables.TableUser, bool) {
	id, _ := ctx.UserValue("id").(string)
	id = strings.TrimSpace(id)
	if id == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "User ID is required")
		return nil, false
	}
	user, err := h.store.GetUser(ctx, id)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to load user")
		return nil, false
	}
	if user == nil {
		SendError(ctx, fasthttp.StatusNotFound, "User not found")
		return nil, false
	}
	return user, true
}

func (h *UsersHandler) userResponse(ctx context.Context, user tables.TableUser) (managedUserResponse, error) {
	roles, err := h.store.GetRolesByUserID(ctx, user.ID)
	if err != nil {
		return managedUserResponse{}, err
	}
	response := managedUserResponse{UserProfile: configstore.NewUserProfile(user), Roles: make([]managedRoleResponse, 0, len(roles))}
	for _, role := range roles {
		response.Roles = append(response.Roles, newManagedRoleResponse(role))
	}
	return response, nil
}

func newManagedRoleResponse(role tables.TableRole) managedRoleResponse {
	return managedRoleResponse{
		ID: role.ID, Name: role.Name, DisplayName: role.DisplayName,
		Permissions: append([]string(nil), role.Permissions...), IsSystem: role.IsSystem, IsImmutable: role.IsImmutable,
	}
}

func usersQueryParams(ctx *fasthttp.RequestCtx) (configstore.UsersQueryParams, bool) {
	params := configstore.UsersQueryParams{Search: string(ctx.QueryArgs().Peek("search")), Limit: 50}
	if rawLimit := ctx.QueryArgs().Peek("limit"); len(rawLimit) > 0 {
		limit, err := strconv.Atoi(string(rawLimit))
		if err != nil || limit <= 0 {
			return configstore.UsersQueryParams{}, false
		}
		params.Limit = limit
	}
	if rawOffset := ctx.QueryArgs().Peek("offset"); len(rawOffset) > 0 {
		offset, err := strconv.Atoi(string(rawOffset))
		if err != nil || offset < 0 {
			return configstore.UsersQueryParams{}, false
		}
		params.Offset = offset
	}
	return params, true
}

func validManagedUserEmail(value string) (string, bool) {
	value = strings.TrimSpace(value)
	address, err := mail.ParseAddress(value)
	return value, err == nil && address.Address == value && strings.Contains(value, "@")
}

func canonicalActorUserID(ctx *fasthttp.RequestCtx) *string {
	actor, _ := ctx.UserValue(schemas.BifrostContextKeyUserID).(string)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return nil
	}
	return &actor
}

func (h *UsersHandler) writeStoreError(ctx *fasthttp.RequestCtx, err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, configstore.ErrNotFound):
		SendError(ctx, fasthttp.StatusNotFound, "User or role not found")
	case errors.Is(err, configstore.ErrAlreadyExists):
		SendError(ctx, fasthttp.StatusConflict, "A user with that email already exists")
	case errors.Is(err, configstore.ErrLastSuperAdmin):
		SendError(ctx, fasthttp.StatusConflict, "At least one active super-admin is required")
	default:
		logger.Error(fmt.Sprintf("user administration operation failed: %v", err))
		SendError(ctx, fasthttp.StatusInternalServerError, "User administration operation failed")
	}
	return true
}
