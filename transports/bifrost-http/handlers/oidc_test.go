package handlers

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/configstore"
	"github.com/valyala/fasthttp"
)

func TestOIDCHandlerProviderListRedactsProviderSecrets(t *testing.T) {
	store := &canonicalSessionAuthStoreStub{authConfig: &configstore.AuthConfig{
		IsEnabled:  true,
		LocalLogin: &configstore.LocalLoginConfig{IsEnabled: true},
		OIDCProviders: []configstore.OIDCProviderConfig{{
			ID: "okta", DisplayName: "Okta", IssuerURL: "https://idp.example.test",
			ClientID: schemas.NewSecretVar("client-id"), ClientSecret: schemas.NewSecretVar("client-secret"), IsEnabled: true,
		}},
	}}
	handler := NewOIDCHandler(store)
	if handler == nil {
		t.Fatal("expected OIDC handler for canonical config store")
	}
	ctx := &fasthttp.RequestCtx{}
	handler.providers(ctx)
	if ctx.Response.StatusCode() != fasthttp.StatusOK {
		t.Fatalf("provider list status = %d, body=%s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	body := string(ctx.Response.Body())
	if body == "" || containsAny(body, "client-secret", "client-id", "issuer_url") {
		t.Fatalf("provider list leaked sensitive configuration: %s", body)
	}
	var response struct {
		LocalLoginEnabled bool `json:"local_login_enabled"`
		Providers         []struct {
			ID string `json:"id"`
		} `json:"providers"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &response); err != nil {
		t.Fatalf("decode provider list: %v", err)
	}
	if !response.LocalLoginEnabled || len(response.Providers) != 1 || response.Providers[0].ID != "okta" {
		t.Fatalf("unexpected provider list response: %#v", response)
	}
}

func TestPublicOIDCRoutesDoNotWhitelistLogout(t *testing.T) {
	for path, want := range map[string]bool{
		"/api/auth/providers":                true,
		"/api/auth/oidc/okta/login":          true,
		"/api/auth/oidc/okta/callback":       true,
		"/api/auth/oidc/okta/logout":         false,
		"/api/auth/oidc/okta/callback/extra": false,
	} {
		if got := isPublicOIDCRoute(path); got != want {
			t.Errorf("isPublicOIDCRoute(%q) = %v, want %v", path, got, want)
		}
	}
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}
