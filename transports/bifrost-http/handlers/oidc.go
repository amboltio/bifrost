package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/fasthttp/router"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/configstore"
	"github.com/maximhq/bifrost/framework/identity"
	"github.com/maximhq/bifrost/transports/bifrost-http/lib"
	"github.com/valyala/fasthttp"
)

// OIDCHandler exposes the browser-facing enterprise login surface. It keeps
// provider metadata public for the login page, while the callback creates the
// same opaque canonical session used by local email/password login.
type OIDCHandler struct {
	configStore configstore.ConfigStore
}

type oidcProviderResponse struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
}

func NewOIDCHandler(store configstore.ConfigStore) *OIDCHandler {
	if store == nil {
		return nil
	}
	return &OIDCHandler{configStore: store}
}

func (h *OIDCHandler) RegisterRoutes(r *router.Router, middlewares ...schemas.BifrostHTTPMiddleware) {
	r.GET("/api/auth/providers", lib.ChainMiddlewares(h.providers, middlewares...))
	r.GET("/api/auth/oidc/{provider}/login", lib.ChainMiddlewares(h.login, middlewares...))
	r.GET("/api/auth/oidc/{provider}/link", lib.ChainMiddlewares(h.link, middlewares...))
	r.GET("/api/auth/oidc/{provider}/callback", lib.ChainMiddlewares(h.callback, middlewares...))
	r.POST("/api/auth/oidc/logout", lib.ChainMiddlewares(h.logout, middlewares...))
}

func (h *OIDCHandler) providers(ctx *fasthttp.RequestCtx) {
	authConfig, err := h.configStore.GetAuthConfig(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to load authentication providers")
		return
	}
	response := struct {
		LocalLoginEnabled bool                   `json:"local_login_enabled"`
		Providers         []oidcProviderResponse `json:"providers"`
	}{Providers: []oidcProviderResponse{}}
	if authConfig != nil && authConfig.IsEnabled {
		for _, method := range authConfig.AuthenticationMethods() {
			if method == "local" {
				response.LocalLoginEnabled = true
				break
			}
		}
		for _, provider := range authConfig.EnabledOIDCProviders() {
			response.Providers = append(response.Providers, oidcProviderResponse{ID: provider.ID, DisplayName: provider.DisplayName})
		}
	}
	SendJSON(ctx, response)
}

func (h *OIDCHandler) login(ctx *fasthttp.RequestCtx) {
	_, provider, err := h.provider(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusNotFound, "OIDC provider not found")
		return
	}
	redirectPath := string(ctx.QueryArgs().Peek("redirect"))
	callbackURL := oidcCallbackURL(ctx, provider.ID)
	oidcStore, ok := h.configStore.(identity.OIDCLoginStore)
	if !ok {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "OIDC authentication is unavailable")
		return
	}
	service := identity.NewOIDCService(oidcStore, nil, nil)
	start, err := service.Begin(ctx, toIdentityOIDCProvider(provider), callbackURL, redirectPath)
	if err != nil {
		if errors.Is(err, identity.ErrOIDCProviderUnavailable) {
			SendError(ctx, fasthttp.StatusBadGateway, "OIDC provider is unavailable")
			return
		}
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid OIDC login request")
		return
	}
	ctx.Redirect(start.AuthorizationURL, fasthttp.StatusFound)
}

func (h *OIDCHandler) callback(ctx *fasthttp.RequestCtx) {
	providerID := strings.TrimSpace(stringValue(ctx.UserValue("provider")))
	authConfig, provider, err := h.providerByID(ctx, providerID)
	if err != nil {
		ctx.Redirect("/login?error=oidc_failed", fasthttp.StatusFound)
		return
	}
	state := string(ctx.QueryArgs().Peek("state"))
	code := string(ctx.QueryArgs().Peek("code"))
	if state == "" || code == "" || string(ctx.QueryArgs().Peek("error")) != "" {
		ctx.Redirect("/login?error=oidc_failed", fasthttp.StatusFound)
		return
	}
	callbackURL := oidcCallbackURL(ctx, provider.ID)
	oidcStore, ok := h.configStore.(identity.OIDCLoginStore)
	if !ok {
		ctx.Redirect("/login?error=oidc_failed", fasthttp.StatusFound)
		return
	}
	service := identity.NewOIDCService(oidcStore, nil, nil)
	result, err := service.Complete(ctx, toIdentityOIDCProvider(provider), callbackURL, state, code)
	if err != nil {
		ctx.Redirect("/login?error=oidc_failed", fasthttp.StatusFound)
		return
	}
	if result.Linked {
		ctx.Redirect(result.RedirectPath, fasthttp.StatusFound)
		return
	}
	sessionStore, ok := h.configStore.(identity.IdentitySessionStore)
	if !ok {
		ctx.Redirect("/login?error=oidc_failed", fasthttp.StatusFound)
		return
	}
	policy := sessionPolicyForAuthConfig(authConfig)
	token, expiresAt, err := identity.NewSessionService(sessionStore, policy, nil).IssueSession(ctx, result.UserID, "oidc", result.ProviderID)
	if err != nil {
		ctx.Redirect("/login?error=oidc_failed", fasthttp.StatusFound)
		return
	}
	setSessionCookie(ctx, token, expiresAt)
	ctx.Redirect(result.RedirectPath, fasthttp.StatusFound)
}

func (h *OIDCHandler) link(ctx *fasthttp.RequestCtx) {
	userID, _ := ctx.UserValue(schemas.BifrostContextKeyUserID).(string)
	userID = strings.TrimSpace(userID)
	if userID == "" {
		SendError(ctx, fasthttp.StatusUnauthorized, "Sign in before linking an identity")
		return
	}
	_, provider, err := h.provider(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusNotFound, "OIDC provider not found")
		return
	}
	oidcStore, ok := h.configStore.(identity.OIDCLoginStore)
	if !ok {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "OIDC authentication is unavailable")
		return
	}
	redirectPath := string(ctx.QueryArgs().Peek("redirect"))
	service := identity.NewOIDCService(oidcStore, nil, nil)
	start, err := service.BeginLink(ctx, toIdentityOIDCProvider(provider), oidcCallbackURL(ctx, provider.ID), redirectPath, userID)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid OIDC link request")
		return
	}
	ctx.Redirect(start.AuthorizationURL, fasthttp.StatusFound)
}

func (h *OIDCHandler) logout(ctx *fasthttp.RequestCtx) {
	if !allowSessionStateChange(ctx) {
		SendError(ctx, fasthttp.StatusForbidden, "Invalid request origin")
		return
	}
	authConfig, err := h.configStore.GetAuthConfig(ctx)
	if err != nil || authConfig == nil || !authConfig.IsEnabled {
		SendError(ctx, fasthttp.StatusForbidden, "Authentication is not enabled")
		return
	}
	token := sessionTokenFromRequest(ctx)
	if token == "" {
		SendError(ctx, fasthttp.StatusUnauthorized, "Unauthorized")
		return
	}
	sessionStore, ok := h.configStore.(identity.IdentitySessionStore)
	if !ok {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "Session storage is unavailable")
		return
	}
	service := identity.NewSessionService(sessionStore, sessionPolicyForAuthConfig(authConfig), nil)
	principal, err := service.AuthenticateSession(context.Background(), token)
	if err != nil {
		clearSessionCookie(ctx)
		SendError(ctx, fasthttp.StatusUnauthorized, "Unauthorized")
		return
	}
	if err := service.RevokeSession(ctx, principal.SessionID, "oidc_logout"); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to invalidate session")
		return
	}
	clearSessionCookie(ctx)
	SendJSON(ctx, map[string]string{"message": "Logout successful"})
}

func (h *OIDCHandler) provider(ctx *fasthttp.RequestCtx) (*configstore.AuthConfig, configstore.OIDCProviderConfig, error) {
	providerID := strings.TrimSpace(stringValue(ctx.UserValue("provider")))
	return h.providerByID(ctx, providerID)
}

func (h *OIDCHandler) providerByID(ctx *fasthttp.RequestCtx, providerID string) (*configstore.AuthConfig, configstore.OIDCProviderConfig, error) {
	authConfig, err := h.configStore.GetAuthConfig(ctx)
	if err != nil || authConfig == nil || !authConfig.IsEnabled || providerID == "" {
		return nil, configstore.OIDCProviderConfig{}, fmt.Errorf("provider unavailable")
	}
	for _, provider := range authConfig.EnabledOIDCProviders() {
		if provider.ID == providerID {
			return authConfig, provider, nil
		}
	}
	return nil, configstore.OIDCProviderConfig{}, fmt.Errorf("provider unavailable")
}

func toIdentityOIDCProvider(provider configstore.OIDCProviderConfig) identity.OIDCProvider {
	var clientID, clientSecret string
	if provider.ClientID != nil {
		clientID = provider.ClientID.GetValue()
	}
	if provider.ClientSecret != nil {
		clientSecret = provider.ClientSecret.GetValue()
	}
	return identity.OIDCProvider{ID: provider.ID, DisplayName: provider.DisplayName, IssuerURL: provider.IssuerURL, ClientID: clientID, ClientSecret: clientSecret, Scopes: append([]string(nil), provider.Scopes...), AllowJITProvisioning: provider.AllowJITProvisioning}
}

func oidcCallbackURL(ctx *fasthttp.RequestCtx, providerID string) string {
	return lib.BuildBaseURL(ctx, "") + "/api/auth/oidc/" + url.PathEscape(providerID) + "/callback"
}

func stringValue(value any) string {
	valueString, _ := value.(string)
	return valueString
}

func sessionTokenFromRequest(ctx *fasthttp.RequestCtx) string {
	authorization := strings.TrimSpace(string(ctx.Request.Header.Peek("Authorization")))
	if strings.HasPrefix(strings.ToLower(authorization), "bearer ") {
		return strings.TrimSpace(authorization[len("Bearer "):])
	}
	return strings.TrimSpace(string(ctx.Request.Header.Cookie("token")))
}
