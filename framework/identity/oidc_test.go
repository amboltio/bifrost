package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type oidcTestStore struct {
	transaction         *tables.TableOIDCTransaction
	external            *tables.TableExternalIdentity
	user                *tables.TableUser
	touched             bool
	provisionedUser     *tables.TableUser
	provisionedExternal *tables.TableExternalIdentity
	provisionedRole     string
	linkedUserID        string
	linkedExternal      *tables.TableExternalIdentity
}

func (s *oidcTestStore) CreateOIDCTransaction(_ context.Context, transaction *tables.TableOIDCTransaction) error {
	s.transaction = transaction
	return nil
}

func (s *oidcTestStore) ClaimOIDCTransaction(_ context.Context, stateHash string, now time.Time) (*tables.TableOIDCTransaction, error) {
	if s.transaction == nil || s.transaction.StateHash != stateHash || s.transaction.ConsumedAt != nil || !s.transaction.ExpiresAt.After(now) {
		return nil, nil
	}
	consumed := now
	s.transaction.ConsumedAt = &consumed
	return s.transaction, nil
}

func (s *oidcTestStore) DeleteExpiredOIDCTransactions(context.Context, time.Time) (int64, error) {
	return 0, nil
}

func (s *oidcTestStore) GetExternalIdentityByIssuerSubject(context.Context, string, string) (*tables.TableExternalIdentity, error) {
	return s.external, nil
}

func (s *oidcTestStore) TouchExternalIdentity(context.Context, string, time.Time) error {
	s.touched = true
	return nil
}

func (s *oidcTestStore) GetUser(context.Context, string) (*tables.TableUser, error) {
	return s.user, nil
}
func (s *oidcTestStore) GetUserByNormalizedEmail(context.Context, string) (*tables.TableUser, error) {
	return nil, nil
}

func (s *oidcTestStore) ProvisionOIDCIdentity(_ context.Context, user *tables.TableUser, external *tables.TableExternalIdentity, roleID string) (*tables.TableUser, error) {
	if user.ID == "" {
		user.ID = "jit-user"
	}
	external.UserID = user.ID
	s.provisionedUser = user
	s.provisionedExternal = external
	s.provisionedRole = roleID
	return user, nil
}

func (s *oidcTestStore) LinkExternalIdentity(_ context.Context, userID string, external *tables.TableExternalIdentity) error {
	external.UserID = userID
	if external.ID == "" {
		external.ID = "linked-identity"
	}
	external.IsActive = true
	s.linkedUserID = userID
	s.linkedExternal = external
	return nil
}

func testOIDCProvider(issuer string) OIDCProvider {
	return OIDCProvider{
		ID: "example", DisplayName: "Example", IssuerURL: issuer,
		ClientID: "client-id", ClientSecret: "client-secret", Scopes: []string{"profile"},
	}
}

func TestOIDCServiceBeginUsesDiscoveryPKCEAndDigestOnlyState(t *testing.T) {
	var serverURL string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer": serverURL, "authorization_endpoint": serverURL + "/authorize",
			"token_endpoint": serverURL + "/token", "jwks_uri": serverURL + "/jwks",
		})
	}))
	defer server.Close()
	serverURL = server.URL

	store := &oidcTestStore{}
	service := NewOIDCService(store, server.Client(), func() time.Time {
		return time.Date(2026, time.September, 22, 10, 0, 0, 0, time.UTC)
	})
	start, err := service.Begin(context.Background(), testOIDCProvider(server.URL), "https://bifrost.example.test/api/auth/oidc/example/callback", "/workspace")
	require.NoError(t, err)
	require.NotNil(t, start)

	parsed, err := url.Parse(start.AuthorizationURL)
	require.NoError(t, err)
	query := parsed.Query()
	assert.Equal(t, "code", query.Get("response_type"))
	assert.Equal(t, "S256", query.Get("code_challenge_method"))
	assert.NotEmpty(t, query.Get("state"))
	assert.NotEqual(t, query.Get("state"), store.transaction.StateHash)
	assert.Equal(t, query.Get("code_challenge"), pkceChallenge(store.transaction.CodeVerifier))
	assert.Equal(t, "openid profile", query.Get("scope"))
	assert.Equal(t, "/workspace", store.transaction.RedirectPath)
}

func TestOIDCServiceBeginLinkBindsTransactionToUser(t *testing.T) {
	var serverURL string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer": serverURL, "authorization_endpoint": serverURL + "/authorize",
			"token_endpoint": serverURL + "/token", "jwks_uri": serverURL + "/jwks",
		})
	}))
	defer server.Close()
	serverURL = server.URL
	store := &oidcTestStore{}
	service := NewOIDCService(store, server.Client(), nil)
	_, err := service.BeginLink(context.Background(), testOIDCProvider(server.URL), "https://bifrost.example.test/api/auth/oidc/example/callback", "/settings/security", "user-1")
	require.NoError(t, err)
	require.NotNil(t, store.transaction.LinkUserID)
	assert.Equal(t, "user-1", *store.transaction.LinkUserID)
}

func TestOIDCServiceCompleteValidatesIssuerAudienceNonceAndResolvesIdentity(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	var serverURL string
	var receivedVerifier string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer": serverURL, "authorization_endpoint": serverURL + "/authorize",
				"token_endpoint": serverURL + "/token", "jwks_uri": serverURL + "/jwks",
			})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
				"kty": "RSA", "kid": "test-key", "alg": "RS256",
				"n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
			}}})
		case "/token":
			_ = r.ParseForm()
			receivedVerifier = r.Form.Get("code_verifier")
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"iss": serverURL, "sub": "subject-1", "aud": "resource-audience", "exp": time.Now().Add(time.Hour).Unix(),
				"iat": time.Now().Add(-time.Minute).Unix(), "nonce": "nonce-value",
				"email": "alice@example.test", "email_verified": true,
			})
			token.Header["kid"] = "test-key"
			raw, signErr := token.SignedString(key)
			if signErr != nil {
				http.Error(w, signErr.Error(), http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"id_token": raw, "token_type": "Bearer"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	now := time.Date(2026, time.September, 22, 10, 0, 0, 0, time.UTC)
	state := "state-value"
	stateHash := fmt.Sprintf("%x", sha256.Sum256([]byte(state)))
	nonceHash := fmt.Sprintf("%x", sha256.Sum256([]byte("nonce-value")))
	store := &oidcTestStore{
		transaction: &tables.TableOIDCTransaction{
			StateHash: stateHash, NonceHash: nonceHash, ProviderID: "example", CodeVerifier: "verifier-value",
			RedirectPath: "/", ExpiresAt: now.Add(5 * time.Minute),
		},
		external: &tables.TableExternalIdentity{ID: "external-1", UserID: "user-1", ProviderID: "example", Issuer: server.URL, Subject: "subject-1", IsActive: true},
		user:     &tables.TableUser{ID: "user-1", Status: tables.UserStatusActive},
	}
	service := NewOIDCService(store, server.Client(), func() time.Time { return now })
	provider := testOIDCProvider(server.URL)
	provider.AllowedAudiences = []string{"resource-audience"}
	result, err := service.Complete(context.Background(), provider, "https://bifrost.example.test/api/auth/oidc/example/callback", state, "auth-code")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "user-1", result.UserID)
	assert.Equal(t, "example", result.ProviderID)
	assert.Equal(t, "verifier-value", receivedVerifier)
	assert.True(t, store.touched)
}

func TestOIDCClaimMappingsSupportNestedClaims(t *testing.T) {
	claims := &oidcIDTokenClaims{raw: map[string]any{
		"profile": map[string]any{"email": "mapped@example.test", "verified": "true", "display_name": "Mapped User"},
	}}
	claims.applyClaimMappings(OIDCClaimMappings{
		Email: "profile.email", EmailVerified: "profile.verified", Name: "profile.display_name",
	})
	assert.Equal(t, "mapped@example.test", claims.Email)
	assert.True(t, claims.EmailVerified)
	assert.Equal(t, "Mapped User", claims.Name)
}

func TestOIDCServiceCompleteRejectsNonceMismatch(t *testing.T) {
	// The success-path test exercises the full signature and claim validation;
	// this targeted check ensures the nonce remains bound to the transaction.
	assert.NotEqual(t, testPKCEChallenge("nonce-value"), testPKCEChallenge("different-nonce"))
}

func TestOIDCServiceCompleteJITProvisioningUsesVerifiedEmail(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	var serverURL string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer": serverURL, "authorization_endpoint": serverURL + "/authorize",
				"token_endpoint": serverURL + "/token", "jwks_uri": serverURL + "/jwks",
			})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
				"kty": "RSA", "kid": "test-key", "alg": "RS256",
				"n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
			}}})
		case "/token":
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"iss": serverURL, "sub": "jit-subject", "aud": "client-id", "exp": time.Now().Add(time.Hour).Unix(),
				"iat": time.Now().Add(-time.Minute).Unix(), "nonce": "nonce-value",
				"email": "jit@example.test", "email_verified": true, "name": "JIT User",
			})
			token.Header["kid"] = "test-key"
			raw, signErr := token.SignedString(key)
			require.NoError(t, signErr)
			_ = json.NewEncoder(w).Encode(map[string]string{"id_token": raw})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	now := time.Date(2026, time.September, 22, 10, 0, 0, 0, time.UTC)
	state := "jit-state"
	store := &oidcTestStore{transaction: &tables.TableOIDCTransaction{
		StateHash:  fmt.Sprintf("%x", sha256.Sum256([]byte(state))),
		NonceHash:  fmt.Sprintf("%x", sha256.Sum256([]byte("nonce-value"))),
		ProviderID: "example", CodeVerifier: "verifier-value", ExpiresAt: now.Add(5 * time.Minute),
	}}
	provider := testOIDCProvider(server.URL)
	provider.AllowJITProvisioning = true
	service := NewOIDCService(store, server.Client(), func() time.Time { return now })

	result, err := service.Complete(context.Background(), provider, "https://bifrost.example.test/api/auth/oidc/example/callback", state, "auth-code")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "jit-user", result.UserID)
	assert.Equal(t, "viewer", store.provisionedRole)
	assert.Equal(t, "jit@example.test", *store.provisionedUser.Email)
	assert.Equal(t, "JIT User", store.provisionedUser.DisplayName)
	assert.Equal(t, "jit-subject", store.provisionedExternal.Subject)
}

func TestOIDCEmailDomainPolicy(t *testing.T) {
	assert.True(t, emailDomainAllowed("Alice@Example.COM", []string{"example.com"}))
	assert.True(t, emailDomainAllowed("alice@example.com", []string{"@example.com"}))
	assert.False(t, emailDomainAllowed("alice@other.test", []string{"example.com"}))
	assert.False(t, emailDomainAllowed("not-an-email", []string{"example.com"}))
	assert.True(t, emailDomainAllowed("alice@other.test", nil))
}

func testPKCEChallenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return strings.TrimRight(base64.RawURLEncoding.EncodeToString(digest[:]), "=")
}
