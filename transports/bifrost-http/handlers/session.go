package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/fasthttp/router"
	"github.com/google/uuid"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/configstore"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/maximhq/bifrost/framework/encrypt"
	"github.com/maximhq/bifrost/framework/identity"
	"github.com/maximhq/bifrost/transports/v2/bifrost-http/lib"
	"github.com/valyala/fasthttp"
)

// SessionHandler manages HTTP requests for session operations
type SessionHandler struct {
	configStore   configstore.ConfigStore
	wsTicketStore *WSTicketStore
	// setupLock is the OSS setup-lock gate (see AuthMiddleware.SetupLockMiddleware). Nil
	// when the gate is not installed (enterprise, or no config store), in which case
	// is-auth-enabled never reports setup_required.
	setupLock     *AuthMiddleware
	loginThrottle *identity.LoginThrottle
}

// AuthStatusResponse is the public login bootstrap contract. auth_type remains
// for older dashboard clients; identity_capabilities gates newer management
// views until the corresponding protected backend slice is implemented.
type AuthStatusResponse struct {
	IsAuthEnabled         bool                                    `json:"is_auth_enabled"`
	HasValidToken         bool                                    `json:"has_valid_token"`
	AuthType              string                                  `json:"auth_type"`
	AuthenticationMethods []string                                `json:"authentication_methods"`
	AuthMethods           []string                                `json:"auth_methods"`
	Providers             []oidcProviderResponse                  `json:"providers,omitempty"`
	IdentityCapabilities  configstore.IdentityFeatureCapabilities `json:"identity_capabilities"`
	// InferenceAuthEnforced reports enforce_auth_on_inference, which gates /v1/*
	// separately from dashboard auth.
	InferenceAuthEnforced bool `json:"inference_auth_enforced"`
	SetupRequired         bool `json:"setup_required"`
	SetupTokenConfigured  bool `json:"setup_token_configured"`
}

func (r AuthStatusResponse) withSetupState(inferenceAuthEnforced, setupRequired, setupTokenConfigured bool) AuthStatusResponse {
	r.InferenceAuthEnforced = inferenceAuthEnforced
	r.SetupRequired = setupRequired
	r.SetupTokenConfigured = setupTokenConfigured
	return r
}

func newAuthStatusResponse(isEnabled bool, hasValidToken bool) AuthStatusResponse {
	return AuthStatusResponse{
		IsAuthEnabled:         isEnabled,
		HasValidToken:         hasValidToken,
		AuthType:              dashboardAuthType(isEnabled),
		AuthenticationMethods: authenticationMethodsForLegacyStatus(isEnabled),
		IdentityCapabilities:  configstore.ImplementedIdentityFeatureCapabilities(),
	}
}

func dashboardAuthTypeForMethods(methods []string) string {
	hasLocal, hasOIDC := false, false
	for _, method := range methods {
		switch method {
		case "local":
			hasLocal = true
		case "oidc":
			hasOIDC = true
		}
	}
	switch {
	case hasLocal:
		return "password"
	case hasOIDC:
		return "sso"
	default:
		return "none"
	}
}

func authenticationMethodsForLegacyStatus(isEnabled bool) []string {
	if !isEnabled {
		return nil
	}
	return []string{"local"}
}

// NewSessionHandler creates a new session handler instance
func NewSessionHandler(configStore configstore.ConfigStore, wsTicketStore *WSTicketStore) *SessionHandler {
	return &SessionHandler{
		configStore:   configStore,
		wsTicketStore: wsTicketStore,
		loginThrottle: identity.NewLoginThrottle(identity.LoginThrottleConfig{}),
	}
}

// SetSetupLock tells the handler the OSS setup-lock gate is installed, so is-auth-enabled
// reports setup_required / setup_token_configured and ws-ticket issues setup-token tickets.
func (h *SessionHandler) SetSetupLock(m *AuthMiddleware) {
	h.setupLock = m
}

// setSetupSessionCookie writes (or, with an empty value, expires) the HttpOnly setup session
// cookie. SameSite=Strict: it only ever needs to ride the dashboard's own requests.
func setSetupSessionCookie(ctx *fasthttp.RequestCtx, value string, expires time.Time) {
	cookie := fasthttp.AcquireCookie()
	defer fasthttp.ReleaseCookie(cookie)
	cookie.SetKey(SetupSessionCookie)
	cookie.SetValue(value)
	cookie.SetExpire(expires)
	cookie.SetPath("/")
	cookie.SetHTTPOnly(true)
	cookie.SetSameSite(fasthttp.CookieSameSiteStrictMode)
	if ctx.IsTLS() || string(ctx.Request.Header.Peek("X-Forwarded-Proto")) == "https" {
		cookie.SetSecure(true)
	}
	ctx.Response.Header.SetCookie(cookie)
}

// startSetupSession handles POST /api/session/setup: while the OSS setup lock is active, it
// trades the setup token (X-Bifrost-Setup-Token, checked here rather than trusting a cookie
// so a session cannot extend itself) for an HttpOnly setup session cookie. The dashboard
// keeps no copy of the token; the cookie authenticates its calls until it expires or
// dashboard auth is enabled.
func (h *SessionHandler) startSetupSession(ctx *fasthttp.RequestCtx) {
	if h.setupLock == nil || h.setupLock.IsDashboardAuthActive() {
		SendError(ctx, fasthttp.StatusConflict, "the setup lock is not active")
		return
	}
	if !h.setupLock.CheckConfiguredSetupToken(string(ctx.Request.Header.Peek(SetupTokenHeader))) {
		SendError(ctx, fasthttp.StatusForbidden, "invalid setup token")
		return
	}
	value, expires, err := h.setupLock.IssueSetupSession(time.Now())
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "failed to start setup session")
		return
	}
	setSetupSessionCookie(ctx, value, expires)
	SendJSON(ctx, map[string]any{"expires_at": expires.UTC().Format(time.RFC3339)})
}

// setupLockState reports whether the setup-lock gate is currently locking the API and
// whether the operator configured a setup token.
func (h *SessionHandler) setupLockState() (setupRequired bool, setupTokenConfigured bool) {
	if h.setupLock == nil {
		return false, false
	}
	return !h.setupLock.IsDashboardAuthActive(), h.setupLock.HasSetupToken()
}

// RegisterRoutes registers the session-related routes
func (h *SessionHandler) RegisterRoutes(r *router.Router, middlewares ...schemas.BifrostHTTPMiddleware) {
	r.POST("/api/session/login", lib.ChainMiddlewares(h.login, middlewares...))
	r.POST("/api/session/logout", lib.ChainMiddlewares(h.logout, middlewares...))
	r.GET("/api/session/is-auth-enabled", lib.ChainMiddlewares(h.isAuthEnabled, middlewares...))
	r.POST("/api/session/ws-ticket", lib.ChainMiddlewares(h.issueWSTicket, middlewares...))
	r.GET("/api/session/current-user", lib.ChainMiddlewares(h.currentUser, middlewares...))
	r.GET("/api/session/sessions", lib.ChainMiddlewares(h.listSessions, middlewares...))
	r.POST("/api/session/logout-all", lib.ChainMiddlewares(h.logoutAll, middlewares...))
	r.DELETE("/api/session/sessions/{id}", lib.ChainMiddlewares(h.revokeOwnedSession, middlewares...))
	r.POST("/api/session/change-password", lib.ChainMiddlewares(h.changePassword, middlewares...))
	r.POST("/api/session/setup", lib.ChainMiddlewares(h.startSetupSession, middlewares...))
}

// isAuthEnabled handles GET /api/session/is-auth-enabled - Check if auth is enabled
func (h *SessionHandler) isAuthEnabled(ctx *fasthttp.RequestCtx) {
	setupRequired, setupTokenConfigured := h.setupLockState()
	if h.configStore == nil {
		SendJSON(ctx, newAuthStatusResponse(false, false).withSetupState(false, setupRequired, setupTokenConfigured))
		return
	}
	// inference_auth_enforced reports enforce_auth_on_inference - a separate toggle from
	// dashboard auth (this endpoint's main subject) that gates /v1/* instead of the
	// dashboard/admin API. Surfaced here so a locked dashboard doesn't look like the whole
	// gateway is secured when this second, easily-missed control is still off.
	inferenceAuthEnforced := false
	if clientConfig, err := h.configStore.GetClientConfig(ctx); err == nil && clientConfig != nil {
		inferenceAuthEnforced = clientConfig.EnforceAuthOnInference
	}
	authConfig, err := h.configStore.GetAuthConfig(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to get auth config: %v", err))
		return
	}
	if authConfig == nil {
		SendJSON(ctx, newAuthStatusResponse(false, false).withSetupState(inferenceAuthEnforced, setupRequired, setupTokenConfigured))
		return
	}
	// Check if the header has a token and is valid (Authorization header or cookie)
	token := ""
	if authHeader := string(ctx.Request.Header.Peek("Authorization")); strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimPrefix(authHeader, "Bearer ")
	}
	if token == "" {
		token = string(ctx.Request.Header.Cookie("token"))
	}
	hasValidToken := false
	if token != "" {
		_, _, hasValidToken = validateDashboardSession(h.configStore, token, sessionPolicyForAuthConfig(authConfig))
	}
	response := newAuthStatusResponse(authConfig.IsEnabled, hasValidToken)
	response.AuthenticationMethods = authConfig.AuthenticationMethods()
	response.AuthMethods = append([]string(nil), response.AuthenticationMethods...)
	response.AuthType = dashboardAuthTypeForMethods(response.AuthenticationMethods)
	response = response.withSetupState(inferenceAuthEnforced, setupRequired, setupTokenConfigured)
	for _, provider := range authConfig.EnabledOIDCProviders() {
		response.Providers = append(response.Providers, oidcProviderResponse{ID: provider.ID, DisplayName: provider.DisplayName})
	}
	SendJSON(ctx, response)
}

// dashboardAuthType reports the dashboard session auth mode for frontend flows.
func dashboardAuthType(isEnabled bool) string {
	if isEnabled {
		return "password"
	}
	return "none"
}

// login handles POST /api/session/login - Login a user
func (h *SessionHandler) login(ctx *fasthttp.RequestCtx) {
	if h.configStore == nil {
		SendError(ctx, fasthttp.StatusForbidden, "Authentication is not enabled")
		return
	}
	if !allowSessionStateChange(ctx) {
		SendError(ctx, fasthttp.StatusForbidden, "Invalid request origin")
		return
	}
	payload := struct {
		Email    string `json:"email"`
		Username string `json:"username"`
		Password string `json:"password"`
	}{}
	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid request payload")
		return
	}

	// Get auth config
	authConfig, err := h.configStore.GetAuthConfig(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to get auth config: %v", err))
		return
	}

	// Check if auth is enabled
	if authConfig == nil || !authConfig.IsEnabled {
		SendError(ctx, fasthttp.StatusForbidden, "Authentication is not enabled")
		return
	}

	// Prefer the canonical identity session after the startup bootstrap has
	// imported the old admin. Canonical credentials are authoritative as soon
	// as the store supports them, including their bcrypt-to-Argon2id upgrade.
	// The fallback remains only for a pre-migration config-store implementation
	// during the one-release compatibility bridge.
	identifier := strings.TrimSpace(payload.Email)
	if identifier == "" {
		identifier = strings.TrimSpace(payload.Username)
	}
	var token string
	var expiresAt time.Time
	if canonicalStore, canonical := h.configStore.(identity.CanonicalUserLookupStore); canonical {
		localAuth, configured := h.localAuthenticationService()
		if !configured || !supportsLocalLogin(authConfig) {
			SendError(ctx, fasthttp.StatusForbidden, "Local authentication is not enabled")
			return
		}
		user, authenticateErr := localAuth.Authenticate(ctx, identifier, payload.Password, ctx.RemoteIP().String())
		if authenticateErr != nil || user == nil {
			if authenticateErr != nil && !errors.Is(authenticateErr, identity.ErrInvalidCredentials) {
				logger.Error("failed canonical local login: %v", authenticateErr)
			}
			SendError(ctx, fasthttp.StatusUnauthorized, "Invalid username or password")
			return
		}
		normalized := authConfig.Normalized()
		policy := identity.SessionPolicy{}
		if normalized.LocalLogin != nil {
			policy.AbsoluteTTL = time.Duration(normalized.LocalLogin.SessionTTLSeconds) * time.Second
			policy.IdleTimeout = time.Duration(normalized.LocalLogin.IdleTimeoutSeconds) * time.Second
		}
		service := identity.NewSessionService(canonicalStore, policy, nil)
		token, expiresAt, err = service.IssueSession(ctx, user.ID, "local", "")
		if err != nil {
			SendError(ctx, fasthttp.StatusUnauthorized, "Invalid username or password")
			return
		}
	} else {
		// Legacy fallback for a store that predates identity tables. Do not
		// enable it once canonical identity support is present: otherwise a
		// changed password could be bypassed with the old config verifier.
		if authConfig.AdminUserName == nil || payload.Username != authConfig.AdminUserName.GetValue() || authConfig.AdminPassword == nil {
			SendError(ctx, fasthttp.StatusUnauthorized, "Invalid username or password")
			return
		}
		compare, compareErr := encrypt.CompareHash(authConfig.AdminPassword.GetValue(), payload.Password)
		if compareErr != nil || !compare {
			SendError(ctx, fasthttp.StatusUnauthorized, "Invalid username or password")
			return
		}
		token = uuid.New().String()
		expiresAt = time.Now().Add(time.Hour * 24 * 30)
		session := &tables.SessionsTable{Token: token, ExpiresAt: expiresAt, CreatedAt: time.Now(), UpdatedAt: time.Now()}
		if err = h.configStore.CreateSession(ctx, session); err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to create session: %v", err))
			return
		}
	}

	setSessionCookie(ctx, token, expiresAt)

	SendJSON(ctx, map[string]any{
		"message": "Login successful",
	})
}

// changePassword verifies a user's current local password before replacing it.
// The canonical store revokes every owned session in the same transaction.
func (h *SessionHandler) changePassword(ctx *fasthttp.RequestCtx) {
	if !allowSessionStateChange(ctx) {
		SendError(ctx, fasthttp.StatusForbidden, "Invalid request origin")
		return
	}
	payload := struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}{}
	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid request payload")
		return
	}
	principal, _, err := h.authenticatedCanonicalSession(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusUnauthorized, "Unauthorized")
		return
	}
	localAuth, configured := h.localAuthenticationService()
	if !configured {
		SendError(ctx, fasthttp.StatusForbidden, "Local authentication is not enabled")
		return
	}
	if err := localAuth.ChangePassword(ctx, principal.UserID, payload.CurrentPassword, payload.NewPassword); err != nil {
		if errors.Is(err, identity.ErrInvalidCredentials) {
			SendError(ctx, fasthttp.StatusUnauthorized, "Invalid username or password")
			return
		}
		logger.Error("failed to change local password: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to change password")
		return
	}
	clearSessionCookie(ctx)
	SendJSON(ctx, map[string]any{"message": "Password changed. Please sign in again."})
}

// logout handles POST /api/session/logout - Logout a user
func (h *SessionHandler) logout(ctx *fasthttp.RequestCtx) {
	if h.configStore == nil {
		SendError(ctx, fasthttp.StatusForbidden, "Authentication is not enabled")
		return
	}
	// Get token from Authorization header
	token := string(ctx.Request.Header.Peek("Authorization"))
	token = strings.TrimPrefix(token, "Bearer ")

	// If no token in header, try to get from cookie
	if token == "" {
		token = string(ctx.Request.Header.Cookie("token"))
	}
	if token != "" && !allowSessionStateChange(ctx) {
		SendError(ctx, fasthttp.StatusForbidden, "Invalid request origin")
		return
	}

	clearSessionCookie(ctx)
	// Drop any setup session as well, so a later return to the setup lock (auth disabled
	// again) cannot be re-entered with a cookie from before.
	setSetupSessionCookie(ctx, "", time.Now().Add(-time.Hour))

	// Revoke canonical sessions so the audit/session-management view retains a
	// bounded record. Old ownerless rows keep the legacy delete behavior until
	// their compatibility reader is removed.
	if token != "" {
		err := h.revokeSessionForLogout(ctx, token)
		if err != nil && !errors.Is(err, configstore.ErrNotFound) {
			logger.Error("failed to delete session during logout: %v", err)
			SendError(ctx, fasthttp.StatusInternalServerError, "Failed to invalidate session. Please try again.")
			return
		}
	}

	SendJSON(ctx, map[string]any{
		"message": "Logout successful",
	})
}

// currentUser returns the profile bound to the session that middleware
// validated. Legacy sessions do not gain a synthetic profile: callers must
// complete the canonical bootstrap path before using identity APIs.
func (h *SessionHandler) currentUser(ctx *fasthttp.RequestCtx) {
	principal, _, err := h.authenticatedCanonicalSession(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusUnauthorized, "Unauthorized")
		return
	}
	user, err := h.configStore.GetUser(ctx, principal.UserID)
	if err != nil || user == nil {
		SendError(ctx, fasthttp.StatusUnauthorized, "Unauthorized")
		return
	}
	SendJSON(ctx, configstore.NewUserProfile(*user))
}

// listSessions returns safe metadata for the authenticated user's devices.
func (h *SessionHandler) listSessions(ctx *fasthttp.RequestCtx) {
	principal, service, err := h.authenticatedCanonicalSession(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusUnauthorized, "Unauthorized")
		return
	}
	sessions, err := service.ListUserSessions(ctx, principal.UserID)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to load sessions")
		return
	}
	SendJSON(ctx, map[string]any{"sessions": sessions, "current_session_id": principal.SessionID})
}

// logoutAll revokes every canonical dashboard session owned by the current
// user. It deliberately includes this session, so a response loss cannot
// leave the browser still authenticated.
func (h *SessionHandler) logoutAll(ctx *fasthttp.RequestCtx) {
	if !allowSessionStateChange(ctx) {
		SendError(ctx, fasthttp.StatusForbidden, "Invalid request origin")
		return
	}
	principal, service, err := h.authenticatedCanonicalSession(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusUnauthorized, "Unauthorized")
		return
	}
	if err := service.RevokeUserSessions(ctx, principal.UserID, "self_service_logout_all"); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to invalidate sessions")
		return
	}
	clearSessionCookie(ctx)
	SendJSON(ctx, map[string]any{"message": "All sessions logged out"})
}

// revokeOwnedSession lets a user terminate another one of their sessions. The
// ownership predicate is part of the SQL update, not inferred from a prior
// client-visible list response.
func (h *SessionHandler) revokeOwnedSession(ctx *fasthttp.RequestCtx) {
	if !allowSessionStateChange(ctx) {
		SendError(ctx, fasthttp.StatusForbidden, "Invalid request origin")
		return
	}
	principal, service, err := h.authenticatedCanonicalSession(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusUnauthorized, "Unauthorized")
		return
	}
	rawID, _ := ctx.UserValue("id").(string)
	sessionID, err := strconv.Atoi(rawID)
	if err != nil || sessionID <= 0 {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid session ID")
		return
	}
	if err := service.RevokeUserSession(ctx, principal.UserID, sessionID, "self_service_revoke"); err != nil {
		if errors.Is(err, configstore.ErrNotFound) {
			SendError(ctx, fasthttp.StatusNotFound, "Session not found")
			return
		}
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to invalidate session")
		return
	}
	if sessionID == principal.SessionID {
		clearSessionCookie(ctx)
	}
	SendJSON(ctx, map[string]any{"message": "Session revoked"})
}

// issueWSTicket handles POST /api/session/ws-ticket - Issue a short-lived ticket for WebSocket auth.
// The caller must already be authenticated (via cookie or Authorization header).
// Returns a one-time-use ticket that the frontend passes as ?ticket= when opening the WebSocket.
func (h *SessionHandler) issueWSTicket(ctx *fasthttp.RequestCtx) {
	if !allowSessionStateChange(ctx) {
		SendError(ctx, fasthttp.StatusForbidden, "Invalid request origin")
		return
	}
	if h.wsTicketStore == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "WebSocket tickets are not available")
		return
	}
	sessionToken, ok := ctx.UserValue(schemas.BifrostContextKeySessionToken).(string)
	if !ok {
		SendError(ctx, fasthttp.StatusUnauthorized, "Unauthorized")
		return
	}
	if sessionToken == "" {
		// This is the case where auth is not configured or not enabled
		sessionToken = "dummy-session"
	}
	ticket, err := h.wsTicketStore.Issue(sessionToken)
	if err != nil {
		logger.Error("failed to issue WS ticket: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to issue WebSocket ticket")
		return
	}
	SendJSON(ctx, map[string]any{
		"ticket": ticket,
	})
}

func (h *SessionHandler) authenticatedCanonicalSession(ctx *fasthttp.RequestCtx) (identity.Principal, *identity.SessionService, error) {
	if h.configStore == nil {
		return identity.Principal{}, nil, identity.ErrUnauthenticated
	}
	token, _ := ctx.UserValue(schemas.BifrostContextKeySessionToken).(string)
	if token == "" {
		return identity.Principal{}, nil, identity.ErrUnauthenticated
	}
	store, ok := h.configStore.(identity.IdentitySessionStore)
	if !ok {
		return identity.Principal{}, nil, identity.ErrUnauthenticated
	}
	policy, err := h.sessionPolicy(ctx)
	if err != nil {
		return identity.Principal{}, nil, err
	}
	service := identity.NewSessionService(store, policy, nil)
	principal, err := service.AuthenticateSession(context.Background(), token)
	if err != nil {
		return identity.Principal{}, nil, err
	}
	if stampedUserID, _ := ctx.UserValue(schemas.BifrostContextKeyUserID).(string); stampedUserID != "" && stampedUserID != principal.UserID {
		return identity.Principal{}, nil, identity.ErrUnauthenticated
	}
	return principal, service, nil
}

func (h *SessionHandler) sessionPolicy(ctx *fasthttp.RequestCtx) (identity.SessionPolicy, error) {
	authConfig, err := h.configStore.GetAuthConfig(ctx)
	if err != nil {
		return identity.SessionPolicy{}, err
	}
	return sessionPolicyForAuthConfig(authConfig), nil
}

func (h *SessionHandler) revokeSessionForLogout(ctx *fasthttp.RequestCtx, token string) error {
	store, ok := h.configStore.(identity.IdentitySessionStore)
	if !ok {
		return h.configStore.DeleteSession(ctx, token)
	}
	session, err := h.configStore.GetSession(ctx, token)
	if err != nil || session == nil || session.UserID == nil {
		return h.configStore.DeleteSession(ctx, token)
	}
	return identity.NewSessionService(store, identity.SessionPolicy{}, nil).RevokeSession(context.Background(), session.ID, "logout")
}

func (h *SessionHandler) localAuthenticationService() (*identity.LocalAuthenticationService, bool) {
	store, ok := h.configStore.(identity.LocalAuthenticationStore)
	if !ok {
		return nil, false
	}
	return identity.NewLocalAuthenticationService(store, identity.NewPasswordService(), h.loginThrottle, nil), true
}

func supportsLocalLogin(authConfig *configstore.AuthConfig) bool {
	if authConfig == nil {
		return false
	}
	for _, method := range authConfig.AuthenticationMethods() {
		if method == "local" {
			return true
		}
	}
	return false
}
