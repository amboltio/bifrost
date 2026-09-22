package handlers

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/configstore"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/valyala/fasthttp"
	"golang.org/x/crypto/bcrypt"
)

func TestSessionHandlerSelfServiceRoutesKeepTokensPrivateAndOwnershipScoped(t *testing.T) {
	now := time.Now().UTC()
	userID := "session-owner"
	store := &canonicalSessionAuthStoreStub{
		user: &tables.TableUser{ID: userID, Email: stringPtr("owner@example.test"), DisplayName: "Owner", Status: tables.UserStatusActive, AuthVersion: 7},
		session: &tables.SessionsTable{
			ID: 42, Token: "raw-session-token-must-not-leak", ExpiresAt: now.Add(time.Hour),
			UserID: &userID, AuthMethod: "local", AuthVersion: 7,
		},
	}
	handler := NewSessionHandler(store, nil)

	listCtx := &fasthttp.RequestCtx{}
	listCtx.SetUserValue(schemas.BifrostContextKeySessionToken, store.session.Token)
	listCtx.SetUserValue(schemas.BifrostContextKeyUserID, userID)
	handler.listSessions(listCtx)
	if listCtx.Response.StatusCode() != fasthttp.StatusOK {
		t.Fatalf("list sessions status = %d, body=%s", listCtx.Response.StatusCode(), listCtx.Response.Body())
	}
	if got := string(listCtx.Response.Body()); strings.Contains(got, store.session.Token) {
		t.Fatalf("session list exposed raw bearer token: %s", got)
	}
	var listResponse struct {
		Sessions []struct {
			ID int `json:"id"`
		} `json:"sessions"`
		CurrentSessionID int `json:"current_session_id"`
	}
	if err := json.Unmarshal(listCtx.Response.Body(), &listResponse); err != nil {
		t.Fatalf("decode session list: %v", err)
	}
	if len(listResponse.Sessions) != 1 || listResponse.Sessions[0].ID != 42 || listResponse.CurrentSessionID != 42 {
		t.Fatalf("unexpected session list response: %#v", listResponse)
	}

	foreignCtx := &fasthttp.RequestCtx{}
	foreignCtx.SetUserValue(schemas.BifrostContextKeySessionToken, store.session.Token)
	foreignCtx.SetUserValue(schemas.BifrostContextKeyUserID, userID)
	foreignCtx.SetUserValue("id", "99")
	handler.revokeOwnedSession(foreignCtx)
	if foreignCtx.Response.StatusCode() != fasthttp.StatusNotFound {
		t.Fatalf("foreign session revoke status = %d, body=%s", foreignCtx.Response.StatusCode(), foreignCtx.Response.Body())
	}
	if store.session.RevokedAt != nil {
		t.Fatal("an unknown session ID must not revoke the current session")
	}
}

func TestSessionHandlerLoginUsesCanonicalCredentialInsteadOfLegacyConfigVerifier(t *testing.T) {
	now := time.Now().UTC()
	email := "admin@example.test"
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("canonical password"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("create bcrypt verifier: %v", err)
	}
	store := &canonicalSessionAuthStoreStub{
		user: &tables.TableUser{ID: "admin-user", Email: &email, NormalizedEmail: stringPtr(email), Status: tables.UserStatusActive, AuthVersion: 1},
		credentials: map[string]*tables.TableCredential{
			tables.CredentialKindLegacyPassword: {ID: "admin-password", UserID: "admin-user", Kind: tables.CredentialKindLegacyPassword, SecretHash: string(passwordHash), Version: 1, IsActive: true},
		},
		authConfig: &configstore.AuthConfig{
			IsEnabled:  true,
			LocalLogin: &configstore.LocalLoginConfig{IsEnabled: true, SessionTTLSeconds: int(time.Hour / time.Second), IdleTimeoutSeconds: int(time.Minute / time.Second)},
		},
	}
	handler := NewSessionHandler(store, nil)
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodPost)
	ctx.Request.SetRequestURI("/api/session/login")
	ctx.Request.SetBodyString(`{"username":"admin@example.test","password":"canonical password"}`)

	handler.login(ctx)
	if ctx.Response.StatusCode() != fasthttp.StatusOK {
		t.Fatalf("login status = %d, body=%s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	if store.session == nil || store.session.UserID == nil || *store.session.UserID != "admin-user" || store.session.AuthMethod != "local" {
		t.Fatalf("login did not issue canonical session: %#v", store.session)
	}
	if _, found := store.credentials[tables.CredentialKindLegacyPassword]; found {
		t.Fatal("successful legacy verifier login must persist the Argon2id credential upgrade")
	}
	if store.session.ExpiresAt.Before(now.Add(59*time.Minute)) || store.session.ExpiresAt.After(now.Add(61*time.Minute)) {
		t.Fatalf("canonical session expiry = %s, want approximately one hour", store.session.ExpiresAt)
	}
}

func stringPtr(value string) *string { return &value }

func TestSessionHandlerLoginAcceptsEmailField(t *testing.T) {
	email := "email-login@example.test"
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("canonical password"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("create bcrypt verifier: %v", err)
	}
	store := &canonicalSessionAuthStoreStub{
		user: &tables.TableUser{ID: "email-user", Email: &email, NormalizedEmail: stringPtr(email), Status: tables.UserStatusActive, AuthVersion: 1},
		credentials: map[string]*tables.TableCredential{
			tables.CredentialKindLegacyPassword: {ID: "email-password", UserID: "email-user", Kind: tables.CredentialKindLegacyPassword, SecretHash: string(passwordHash), Version: 1, IsActive: true},
		},
		authConfig: &configstore.AuthConfig{IsEnabled: true, LocalLogin: &configstore.LocalLoginConfig{IsEnabled: true}},
	}
	handler := NewSessionHandler(store, nil)
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodPost)
	ctx.Request.SetRequestURI("/api/session/login")
	ctx.Request.SetBodyString(`{"email":"email-login@example.test","password":"canonical password"}`)

	handler.login(ctx)
	if ctx.Response.StatusCode() != fasthttp.StatusOK {
		t.Fatalf("login status = %d, body=%s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	if store.session == nil || store.session.UserID == nil || *store.session.UserID != "email-user" {
		t.Fatalf("email login did not issue canonical session: %#v", store.session)
	}
}
