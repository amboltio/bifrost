package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/fasthttp/router"
	"github.com/google/uuid"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/configstore"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/maximhq/bifrost/framework/identity"
	"github.com/maximhq/bifrost/transports/v2/bifrost-http/lib"
	"github.com/valyala/fasthttp"
)

type dashboardPolicyStore interface {
	GetDashboardAuthPolicy(context.Context) (*configstore.DashboardAuthPolicy, error)
	SaveDashboardAuthPolicy(context.Context, uint64, *configstore.AuthConfig, *tables.TableAuditEvent, *tables.TableOutboxEvent) error
}

type AuthSettingsHandler struct {
	sessions   *SessionHandler
	store      configstore.ConfigStore
	middleware *AuthMiddleware
}

func NewAuthSettingsHandler(store configstore.ConfigStore, middleware *AuthMiddleware) *AuthSettingsHandler {
	return &AuthSettingsHandler{sessions: NewSessionHandler(store, nil), store: store, middleware: middleware}
}

func (h *AuthSettingsHandler) RegisterRoutes(r *router.Router, middlewares ...schemas.BifrostHTTPMiddleware) {
	r.GET("/api/auth/settings", lib.ChainMiddlewares(h.get, middlewares...))
	r.PUT("/api/auth/settings", lib.ChainMiddlewares(h.update, middlewares...))
}

func (h *AuthSettingsHandler) authorize(ctx *fasthttp.RequestCtx, write bool) (string, bool) {
	principal, _, err := h.sessions.authenticatedCanonicalSession(ctx)
	if err != nil {
		SendError(ctx, 401, "Sign in with a user account")
		return "", false
	}
	roles, err := h.store.GetUserRoleAssignments(ctx, principal.UserID)
	if err != nil {
		SendError(ctx, 503, "Unable to verify permissions")
		return "", false
	}
	allowed := false
	for _, role := range roles {
		if role.RoleID == tables.RoleIDSuperAdmin {
			allowed = true
		}
	}
	if !allowed {
		SendError(ctx, 403, "Only a super administrator can manage login settings")
		return "", false
	}
	if write {
		if !allowSessionStateChange(ctx) {
			SendError(ctx, 403, "Invalid request origin")
			return "", false
		}
		token, _ := ctx.UserValue(schemas.BifrostContextKeySessionToken).(string)
		session, err := h.store.GetSession(ctx, token)
		now := time.Now()
		if err != nil || session == nil || session.CreatedAt.After(now) || now.Sub(session.CreatedAt) > superAdminAssignmentFreshAuthWindow {
			SendError(ctx, 403, "Sign in again before changing login settings")
			return "", false
		}
	}
	return principal.UserID, true
}

func (h *AuthSettingsHandler) get(ctx *fasthttp.RequestCtx) {
	if _, ok := h.authorize(ctx, false); !ok {
		return
	}
	store, ok := h.store.(dashboardPolicyStore)
	if !ok {
		SendError(ctx, 503, "Login settings are unavailable")
		return
	}
	policy, err := store.GetDashboardAuthPolicy(ctx)
	if err != nil {
		SendError(ctx, 503, "Unable to load login settings")
		return
	}
	copy := *policy
	copy.AuthConfig = *policy.AuthConfig.Redacted()
	copy.AuthConfig.AdminUserName, copy.AuthConfig.AdminPassword = nil, nil
	SendJSON(ctx, copy)
}

func (h *AuthSettingsHandler) update(ctx *fasthttp.RequestCtx) {
	actor, ok := h.authorize(ctx, true)
	if !ok {
		return
	}
	store, ok := h.store.(dashboardPolicyStore)
	if !ok {
		SendError(ctx, 503, "Login settings are unavailable")
		return
	}
	var payload configstore.DashboardAuthPolicy
	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, 400, "Invalid login settings")
		return
	}
	current, err := store.GetDashboardAuthPolicy(ctx)
	if err != nil {
		SendError(ctx, 503, "Unable to load login settings")
		return
	}
	if current.Revision != payload.Revision {
		SendError(ctx, 409, configstore.ErrAuthPolicyConflict.Error())
		return
	}
	for i := range payload.AuthConfig.OIDCProviders {
		provider := &payload.AuthConfig.OIDCProviders[i]
		for _, old := range current.AuthConfig.OIDCProviders {
			if old.ID != provider.ID {
				continue
			}
			if provider.ClientID.ShouldPreserveStored() {
				provider.ClientID = old.ClientID
			}
			if provider.ClientSecret.ShouldPreserveStored() {
				provider.ClientSecret = old.ClientSecret
			}
		}
	}
	if !payload.AuthConfig.IsEnabled || payload.AuthConfig.AdminUserName != nil || payload.AuthConfig.AdminPassword != nil {
		SendError(ctx, 400, "User authentication is required; manage credentials in Users")
		return
	}
	if err := payload.AuthConfig.Validate(); err != nil {
		SendError(ctx, 400, err.Error())
		return
	}
	// Validate enabled providers before committing a configuration that may disable local login.
	for _, provider := range payload.AuthConfig.EnabledOIDCProviders() {
		oidcStore, ok := h.store.(identity.OIDCLoginStore)
		if !ok {
			SendError(ctx, 503, "OIDC verification unavailable")
			return
		}
		if _, err := identity.NewOIDCService(oidcStore, nil, nil).VerifyProvider(ctx, toIdentityOIDCProvider(provider)); err != nil {
			SendError(ctx, 400, "Unable to verify the configured OIDC provider")
			return
		}
	}
	id := uuid.NewString()
	audit := &tables.TableAuditEvent{ID: id, ActorPrincipal: "user:" + actor, TargetType: "authentication", Action: "identity.auth_policy.updated", OccurredAt: time.Now().UTC(), ChangedFields: map[string]any{"revision": payload.Revision + 1}}
	outbox := &tables.TableOutboxEvent{Topic: "identity.auth_policy.changed", DeduplicationKey: "identity.auth_policy:" + id, Payload: map[string]any{"revision": payload.Revision + 1}}
	if err := store.SaveDashboardAuthPolicy(ctx, payload.Revision, &payload.AuthConfig, audit, outbox); err != nil {
		if errors.Is(err, configstore.ErrAuthPolicyConflict) {
			SendError(ctx, 409, err.Error())
		} else {
			SendError(ctx, 400, err.Error())
		}
		return
	}
	if h.middleware != nil {
		h.middleware.UpdateAuthConfig(&payload.AuthConfig)
	}
	clearSessionCookie(ctx)
	SendJSON(ctx, map[string]any{"revision": payload.Revision + 1, "reauthentication_required": true})
}
