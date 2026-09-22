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
	"github.com/google/uuid"
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
	configstore.AuditedUserManagementStore
	configstore.AuditedRecoveryTokenStore
	GetUser(ctx context.Context, id string) (*tables.TableUser, error)
	DisableUser(ctx context.Context, id string, disabledAt time.Time) error
	RevokeAllUserSessions(ctx context.Context, userID string, revokedAt time.Time) (int64, error)
}

type userTeamMembershipHandlerStore interface {
	configstore.UserTeamMembershipStore
}

type externalIdentityManagementHandlerStore interface {
	configstore.ExternalIdentityManagementStore
}

// UsersHandler manages canonical users, role grants, and administrator-issued
// reset tokens. Its routes rely on IdentityAuthorizationMiddleware for the
// resource-specific permission check and keep a small store contract for
// direct handler tests.
type UsersHandler struct {
	store         userManagementHandlerStore
	roleStore     configstore.RoleManagementStore
	teamStore     userTeamMembershipHandlerStore
	identityStore externalIdentityManagementHandlerStore
	passwords     *identity.PasswordService
	recovery      *identity.RecoveryService
	now           func() time.Time
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
		store: managementStore, roleStore: optionalRoleManagementStore(store), teamStore: optionalUserTeamStore(store), identityStore: optionalExternalIdentityStore(store), passwords: passwords,
		recovery: identity.NewRecoveryService(managementStore, passwords, nil), now: time.Now,
	}
}

func optionalRoleManagementStore(store any) configstore.RoleManagementStore {
	roleStore, _ := store.(configstore.RoleManagementStore)
	return roleStore
}

func optionalUserTeamStore(store any) userTeamMembershipHandlerStore {
	teamStore, _ := store.(userTeamMembershipHandlerStore)
	return teamStore
}

func optionalExternalIdentityStore(store any) externalIdentityManagementHandlerStore {
	identityStore, _ := store.(externalIdentityManagementHandlerStore)
	return identityStore
}

// RegisterRoutes installs the user administration surface below governance so
// it follows the dashboard's established management route namespace.
func (h *UsersHandler) RegisterRoutes(r *router.Router, middlewares ...schemas.BifrostHTTPMiddleware) {
	r.GET("/api/governance/users", lib.ChainMiddlewares(h.listUsers, middlewares...))
	r.POST("/api/governance/users", lib.ChainMiddlewares(h.createUser, middlewares...))
	r.GET("/api/governance/roles", lib.ChainMiddlewares(h.listRoles, middlewares...))
	r.POST("/api/governance/roles", lib.ChainMiddlewares(h.createRole, middlewares...))
	r.GET("/api/governance/roles/{id}", lib.ChainMiddlewares(h.getRole, middlewares...))
	r.PUT("/api/governance/roles/{id}", lib.ChainMiddlewares(h.updateRole, middlewares...))
	r.PATCH("/api/governance/roles/{id}", lib.ChainMiddlewares(h.updateRole, middlewares...))
	r.DELETE("/api/governance/roles/{id}", lib.ChainMiddlewares(h.deleteRole, middlewares...))
	r.GET("/api/governance/roles/{id}/permissions", lib.ChainMiddlewares(h.getRolePermissions, middlewares...))
	r.PUT("/api/governance/roles/{id}/permissions", lib.ChainMiddlewares(h.updateRolePermissions, middlewares...))
	r.GET("/api/governance/users/{id}/teams", lib.ChainMiddlewares(h.listTeams, middlewares...))
	r.PUT("/api/governance/users/{id}/teams", lib.ChainMiddlewares(h.replaceTeams, middlewares...))
	r.GET("/api/governance/users/{id}/identities", lib.ChainMiddlewares(h.listIdentities, middlewares...))
	r.DELETE("/api/governance/users/{id}/identities/{identity}", lib.ChainMiddlewares(h.unlinkIdentity, middlewares...))
	r.GET("/api/governance/users/{id}", lib.ChainMiddlewares(h.getUser, middlewares...))
	r.PATCH("/api/governance/users/{id}", lib.ChainMiddlewares(h.updateUser, middlewares...))
	r.PUT("/api/governance/users/{id}", lib.ChainMiddlewares(h.updateUser, middlewares...))
	r.DELETE("/api/governance/users/{id}", lib.ChainMiddlewares(h.disableUser, middlewares...))
	r.POST("/api/governance/users/{id}/reset-password", lib.ChainMiddlewares(h.resetPassword, middlewares...))
	r.POST("/api/governance/users/{id}/revoke-sessions", lib.ChainMiddlewares(h.revokeSessions, middlewares...))
	r.PUT("/api/governance/users/{id}/roles", lib.ChainMiddlewares(h.replaceRoles, middlewares...))
}

type managedTeamResponse struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	CustomerID *string `json:"customer_id,omitempty"`
	Source     string  `json:"source"`
	ProviderID *string `json:"provider_id,omitempty"`
}

type managedExternalIdentityResponse struct {
	ID         string     `json:"id"`
	ProviderID string     `json:"provider_id"`
	Issuer     string     `json:"issuer"`
	Subject    string     `json:"subject"`
	IsActive   bool       `json:"is_active"`
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

func (h *UsersHandler) listIdentities(ctx *fasthttp.RequestCtx) {
	if h.identityStore == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "External identities are unavailable")
		return
	}
	user, ok := h.requiredUser(ctx)
	if !ok {
		return
	}
	identities, err := h.identityStore.ListExternalIdentitiesByUserID(ctx, user.ID)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to load external identities")
		return
	}
	response := make([]managedExternalIdentityResponse, 0, len(identities))
	for _, identity := range identities {
		response = append(response, managedExternalIdentityResponse{
			ID: identity.ID, ProviderID: identity.ProviderID, Issuer: identity.Issuer, Subject: identity.Subject,
			IsActive: identity.IsActive, LastSeenAt: identity.LastSeenAt, CreatedAt: identity.CreatedAt,
		})
	}
	SendJSON(ctx, map[string]any{"identities": response})
}

func (h *UsersHandler) unlinkIdentity(ctx *fasthttp.RequestCtx) {
	if h.identityStore == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "External identities are unavailable")
		return
	}
	if !allowSessionStateChange(ctx) {
		SendError(ctx, fasthttp.StatusForbidden, "Invalid request origin")
		return
	}
	user, ok := h.requiredUser(ctx)
	if !ok {
		return
	}
	identityID, _ := ctx.UserValue("identity").(string)
	identityID = strings.TrimSpace(identityID)
	if identityID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "Identity ID is required")
		return
	}
	auditEvent, outboxEvent := h.userAudit(ctx, user.ID, "identity.user.external_identity_revoked", map[string]any{"identity_id": identityID})
	err := h.identityStore.SetExternalIdentityActiveAudited(ctx, user.ID, identityID, false, auditEvent, outboxEvent)
	if errors.Is(err, configstore.ErrLastAuthenticationMethod) {
		SendError(ctx, fasthttp.StatusConflict, "At least one active authentication method is required")
		return
	}
	if h.writeStoreError(ctx, err) {
		return
	}
	ctx.SetStatusCode(fasthttp.StatusNoContent)
}

func (h *UsersHandler) listTeams(ctx *fasthttp.RequestCtx) {
	if h.teamStore == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "Team memberships are unavailable")
		return
	}
	user, ok := h.requiredUser(ctx)
	if !ok {
		return
	}
	memberships, err := h.teamStore.ListUserTeamMemberships(ctx, user.ID)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to load team memberships")
		return
	}
	response := make([]managedTeamResponse, 0, len(memberships))
	for _, membership := range memberships {
		team := managedTeamResponse{ID: membership.TeamID, Source: membership.Source, ProviderID: membership.ProviderID}
		if membership.Team != nil {
			team.ID, team.Name, team.CustomerID = membership.Team.ID, membership.Team.Name, membership.Team.CustomerID
		}
		response = append(response, team)
	}
	SendJSON(ctx, map[string]any{"teams": response})
}

func (h *UsersHandler) replaceTeams(ctx *fasthttp.RequestCtx) {
	if h.teamStore == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "Team memberships are unavailable")
		return
	}
	if !allowSessionStateChange(ctx) {
		SendError(ctx, fasthttp.StatusForbidden, "Invalid request origin")
		return
	}
	user, ok := h.requiredUser(ctx)
	if !ok {
		return
	}
	request := struct {
		TeamIDs []string `json:"team_ids"`
	}{}
	if err := json.Unmarshal(ctx.PostBody(), &request); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid request payload")
		return
	}
	auditEvent, outboxEvent := h.userAudit(ctx, user.ID, "identity.user.teams_updated", map[string]any{"team_ids": request.TeamIDs})
	err := h.teamStore.ReplaceManualUserTeamMembershipsAudited(ctx, user.ID, request.TeamIDs, canonicalActorUserID(ctx), auditEvent, outboxEvent)
	if h.writeStoreError(ctx, err) {
		return
	}
	h.listTeams(ctx)
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

func (h *UsersHandler) getRole(ctx *fasthttp.RequestCtx) {
	if h.roleStore == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "Role management is unavailable")
		return
	}
	id, _ := ctx.UserValue("id").(string)
	role, err := h.roleStore.GetRole(ctx, strings.TrimSpace(id))
	if err == nil && role == nil {
		err = configstore.ErrNotFound
	}
	if h.writeRoleStoreError(ctx, err) {
		return
	}
	SendJSON(ctx, newManagedRoleResponse(*role))
}

func (h *UsersHandler) getRolePermissions(ctx *fasthttp.RequestCtx) {
	if h.roleStore == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "Role management is unavailable")
		return
	}
	id, _ := ctx.UserValue("id").(string)
	role, err := h.roleStore.GetRole(ctx, strings.TrimSpace(id))
	if err == nil && role == nil {
		err = configstore.ErrNotFound
	}
	if h.writeRoleStoreError(ctx, err) {
		return
	}
	SendJSON(ctx, map[string]any{"role_id": role.ID, "permissions": append([]string(nil), role.Permissions...)})
}

func (h *UsersHandler) createRole(ctx *fasthttp.RequestCtx) {
	if h.roleStore == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "Role management is unavailable")
		return
	}
	if !allowSessionStateChange(ctx) {
		SendError(ctx, fasthttp.StatusForbidden, "Invalid request origin")
		return
	}
	request := struct {
		ID          string   `json:"id"`
		Name        string   `json:"name"`
		DisplayName string   `json:"display_name"`
		Permissions []string `json:"permissions"`
	}{}
	if err := json.Unmarshal(ctx.PostBody(), &request); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid request payload")
		return
	}
	role := &tables.TableRole{ID: strings.TrimSpace(request.ID), Name: strings.TrimSpace(request.Name), DisplayName: strings.TrimSpace(request.DisplayName), Permissions: request.Permissions}
	if role.ID == "" {
		role.ID = uuid.NewString()
	}
	auditEvent, outboxEvent := h.roleAudit(ctx, role.ID, "identity.role.created", map[string]any{"name": role.Name, "permissions": role.Permissions})
	created, err := h.roleStore.CreateRoleAudited(ctx, role, auditEvent, outboxEvent)
	if h.writeRoleStoreError(ctx, err) {
		return
	}
	SendJSONWithStatus(ctx, newManagedRoleResponse(*created), fasthttp.StatusCreated)
}

func (h *UsersHandler) updateRole(ctx *fasthttp.RequestCtx) {
	if h.roleStore == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "Role management is unavailable")
		return
	}
	if !allowSessionStateChange(ctx) {
		SendError(ctx, fasthttp.StatusForbidden, "Invalid request origin")
		return
	}
	id, _ := ctx.UserValue("id").(string)
	role, err := h.roleStore.GetRole(ctx, strings.TrimSpace(id))
	if err == nil && role == nil {
		err = configstore.ErrNotFound
	}
	if h.writeRoleStoreError(ctx, err) {
		return
	}
	request := struct {
		DisplayName *string  `json:"display_name"`
		Permissions []string `json:"permissions"`
	}{}
	if err := json.Unmarshal(ctx.PostBody(), &request); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid request payload")
		return
	}
	displayName := role.DisplayName
	if request.DisplayName != nil {
		displayName = strings.TrimSpace(*request.DisplayName)
	}
	permissions := role.Permissions
	if request.Permissions != nil {
		permissions = request.Permissions
	}
	auditEvent, outboxEvent := h.roleAudit(ctx, role.ID, "identity.role.updated", map[string]any{"permissions": permissions})
	updated, err := h.roleStore.UpdateRoleAudited(ctx, role.ID, displayName, permissions, auditEvent, outboxEvent)
	if h.writeRoleStoreError(ctx, err) {
		return
	}
	SendJSON(ctx, newManagedRoleResponse(*updated))
}

func (h *UsersHandler) updateRolePermissions(ctx *fasthttp.RequestCtx) {
	if h.roleStore == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "Role management is unavailable")
		return
	}
	if !allowSessionStateChange(ctx) {
		SendError(ctx, fasthttp.StatusForbidden, "Invalid request origin")
		return
	}
	id, _ := ctx.UserValue("id").(string)
	role, err := h.roleStore.GetRole(ctx, strings.TrimSpace(id))
	if err == nil && role == nil {
		err = configstore.ErrNotFound
	}
	if h.writeRoleStoreError(ctx, err) {
		return
	}
	request := struct {
		Permissions []string `json:"permissions"`
	}{}
	if err := json.Unmarshal(ctx.PostBody(), &request); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid request payload")
		return
	}
	auditEvent, outboxEvent := h.roleAudit(ctx, role.ID, "identity.role.permissions_updated", map[string]any{"permissions": request.Permissions})
	updated, err := h.roleStore.UpdateRoleAudited(ctx, role.ID, role.DisplayName, request.Permissions, auditEvent, outboxEvent)
	if h.writeRoleStoreError(ctx, err) {
		return
	}
	SendJSON(ctx, map[string]any{"role_id": updated.ID, "permissions": updated.Permissions})
}

func (h *UsersHandler) deleteRole(ctx *fasthttp.RequestCtx) {
	if h.roleStore == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "Role management is unavailable")
		return
	}
	if !allowSessionStateChange(ctx) {
		SendError(ctx, fasthttp.StatusForbidden, "Invalid request origin")
		return
	}
	id, _ := ctx.UserValue("id").(string)
	auditEvent, outboxEvent := h.roleAudit(ctx, strings.TrimSpace(id), "identity.role.deleted", nil)
	if h.writeRoleStoreError(ctx, h.roleStore.DeleteRoleAudited(ctx, strings.TrimSpace(id), auditEvent, outboxEvent)) {
		return
	}
	ctx.SetStatusCode(fasthttp.StatusNoContent)
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
		ID:    uuid.NewString(),
		Email: &email, DisplayName: strings.TrimSpace(request.DisplayName), Status: tables.UserStatusActive,
		CreatedByUserID: actorID,
	}
	auditEvent, outboxEvent := h.userAudit(ctx, user.ID, "identity.user.created", map[string]any{"role_ids": request.RoleIDs})
	created, err := h.store.CreateManagedUserAudited(ctx, user, &tables.TableCredential{SecretHash: passwordHash}, request.RoleIDs, auditEvent, outboxEvent)
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
	displayName := strings.TrimSpace(*request.DisplayName)
	auditEvent, outboxEvent := h.userAudit(ctx, user.ID, "identity.user.updated", map[string]any{"fields": []string{"display_name"}})
	if err := h.store.UpdateUserDisplayNameAudited(ctx, user.ID, displayName, auditEvent, outboxEvent); h.writeStoreError(ctx, err) {
		return
	}
	user.DisplayName = displayName
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
	disabledAt := h.now().UTC()
	auditEvent, outboxEvent := h.userAudit(ctx, user.ID, "identity.user.disabled", map[string]any{"status": tables.UserStatusDisabled})
	if err := h.store.DisableUserAudited(ctx, user.ID, disabledAt, auditEvent, outboxEvent); h.writeStoreError(ctx, err) {
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
	auditEvent, outboxEvent := h.userAudit(ctx, user.ID, "identity.user.password_reset_issued", map[string]any{"purpose": tables.RecoveryTokenPurposeReset})
	rawToken, expiresAt, err := h.recovery.IssueAudited(ctx, user.ID, tables.RecoveryTokenPurposeReset, canonicalActorUserID(ctx), auditEvent, outboxEvent)
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
	auditEvent, outboxEvent := h.userAudit(ctx, user.ID, "identity.user.sessions_revoked", nil)
	revoked, err := h.store.RevokeAllUserSessionsAudited(ctx, user.ID, h.now().UTC(), auditEvent, outboxEvent)
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
	auditEvent, outboxEvent := h.userAudit(ctx, user.ID, "identity.user.roles_updated", map[string]any{"role_ids": request.RoleIDs})
	if err := h.store.ReplaceUserRoleAssignmentsAudited(ctx, user.ID, request.RoleIDs, canonicalActorUserID(ctx), auditEvent, outboxEvent); h.writeStoreError(ctx, err) {
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

func (h *UsersHandler) userAudit(ctx *fasthttp.RequestCtx, targetUserID, action string, changedFields map[string]any) (*tables.TableAuditEvent, *tables.TableOutboxEvent) {
	eventID := uuid.NewString()
	actorPrincipal := "legacy:local_admin"
	if actor := canonicalActorUserID(ctx); actor != nil {
		actorPrincipal = "user:" + *actor
	}
	var requestID *string
	if value, ok := ctx.UserValue(schemas.BifrostContextKeyRequestID).(string); ok && strings.TrimSpace(value) != "" {
		value = strings.TrimSpace(value)
		requestID = &value
	}
	return &tables.TableAuditEvent{
		ID: eventID, ActorPrincipal: actorPrincipal, TargetType: "user", TargetID: &targetUserID,
		Action: action, RequestID: requestID, OccurredAt: h.now().UTC(), ChangedFields: changedFields,
	}, &tables.TableOutboxEvent{
		Topic: "identity.user.changed", DeduplicationKey: "identity.user:" + eventID,
		Payload: map[string]any{"user_id": targetUserID, "action": action},
	}
}

func (h *UsersHandler) roleAudit(ctx *fasthttp.RequestCtx, targetRoleID, action string, changedFields map[string]any) (*tables.TableAuditEvent, *tables.TableOutboxEvent) {
	eventID := uuid.NewString()
	actorPrincipal := "legacy:local_admin"
	if actor := canonicalActorUserID(ctx); actor != nil {
		actorPrincipal = "user:" + *actor
	}
	var requestID *string
	if value, ok := ctx.UserValue(schemas.BifrostContextKeyRequestID).(string); ok && strings.TrimSpace(value) != "" {
		value = strings.TrimSpace(value)
		requestID = &value
	}
	return &tables.TableAuditEvent{
		ID: eventID, ActorPrincipal: actorPrincipal, TargetType: "role", TargetID: &targetRoleID,
		Action: action, RequestID: requestID, OccurredAt: h.now().UTC(), ChangedFields: changedFields,
	}, &tables.TableOutboxEvent{
		Topic: "identity.role.changed", DeduplicationKey: "identity.role:" + eventID,
		Payload: map[string]any{"role_id": targetRoleID, "action": action},
	}
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

func (h *UsersHandler) writeRoleStoreError(ctx *fasthttp.RequestCtx, err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, configstore.ErrNotFound):
		SendError(ctx, fasthttp.StatusNotFound, "Role not found")
	case errors.Is(err, configstore.ErrAlreadyExists):
		SendError(ctx, fasthttp.StatusConflict, "A role with that name already exists")
	case errors.Is(err, configstore.ErrRoleImmutable):
		SendError(ctx, fasthttp.StatusConflict, "System roles cannot be changed")
	case errors.Is(err, configstore.ErrRoleInUse):
		SendError(ctx, fasthttp.StatusConflict, "Role is assigned to users")
	case errors.Is(err, configstore.ErrInvalidPermission):
		SendError(ctx, fasthttp.StatusBadRequest, "Role contains an unknown permission")
	default:
		logger.Error(fmt.Sprintf("role administration operation failed: %v", err))
		SendError(ctx, fasthttp.StatusInternalServerError, "Role administration operation failed")
	}
	return true
}
