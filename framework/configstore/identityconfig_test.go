package configstore

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	bifrost "github.com/maximhq/bifrost/core"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/maximhq/bifrost/framework/encrypt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthConfigPersistenceKeepsLoginPolicyWithoutGlobalCredentials(t *testing.T) {
	store := setupLegacyBootstrapStore(t)
	config := &AuthConfig{IsEnabled: true, LocalLogin: &LocalLoginConfig{
		IsEnabled: true, SessionTTLSeconds: 7200, IdleTimeoutSeconds: 600,
	}}
	require.NoError(t, store.UpdateAuthConfig(context.Background(), config))
	loaded, err := store.GetAuthConfig(context.Background())
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, config.LocalLogin, loaded.LocalLogin)
	assert.Nil(t, loaded.AdminUserName)
	assert.Nil(t, loaded.AdminPassword)
}

// TestAuthConfigPersistenceRoundTripsWithAndWithoutEncryptionKey protects
// installs that run without an encryption key: the stored policy must be
// readable back, and only flagged encrypted when it really was.
func TestAuthConfigPersistenceRoundTripsWithAndWithoutEncryptionKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  string
	}{{"without key", ""}, {"with key", testEncryptionKey}} {
		t.Run(tc.name, func(t *testing.T) {
			encrypt.Init(tc.key, bifrost.NewDefaultLogger(schemas.LogLevelInfo))
			t.Cleanup(func() { encrypt.Init(testEncryptionKey, bifrost.NewDefaultLogger(schemas.LogLevelInfo)) })
			store := setupLegacyBootstrapStore(t)
			config := &AuthConfig{IsEnabled: true, LocalLogin: &LocalLoginConfig{IsEnabled: true, SessionTTLSeconds: 7200, IdleTimeoutSeconds: 600}}
			require.NoError(t, store.UpdateAuthConfig(context.Background(), config))
			loaded, err := store.GetAuthConfig(context.Background())
			require.NoError(t, err)
			require.NotNil(t, loaded)
			assert.Equal(t, config.LocalLogin, loaded.LocalLogin)
		})
	}
}

// TestStoredAuthPolicyKeepsSecretReferencesNotResolvedValues pins that a
// provider secret supplied as an external reference is persisted as the
// reference only; the resolved environment value never reaches the row.
func TestStoredAuthPolicyKeepsSecretReferencesNotResolvedValues(t *testing.T) {
	encrypt.Init("", bifrost.NewDefaultLogger(schemas.LogLevelInfo))
	t.Cleanup(func() { encrypt.Init(testEncryptionKey, bifrost.NewDefaultLogger(schemas.LogLevelInfo)) })
	t.Setenv("TEST_OIDC_CLIENT_SECRET", "resolved-secret-value")
	store := setupLegacyBootstrapStore(t)
	config := &AuthConfig{IsEnabled: true, OIDCProviders: []OIDCProviderConfig{{
		ID: "entra", DisplayName: "Entra", IssuerURL: "https://login.example.test/tenant/v2.0",
		ClientID: schemas.NewSecretVar("client-id"), ClientSecret: schemas.NewSecretVar("env.TEST_OIDC_CLIENT_SECRET"), IsEnabled: true,
	}}}
	require.NoError(t, store.UpdateAuthConfig(context.Background(), config))

	var row tables.TableGovernanceConfig
	require.NoError(t, store.DB().First(&row, "key = ?", tables.ConfigDashboardAuthPolicyKey).Error)
	assert.NotContains(t, row.Value, "resolved-secret-value")
	assert.Contains(t, row.Value, "env.TEST_OIDC_CLIENT_SECRET")
}

func TestAuthConfigExplicitLocalDisableOverridesLegacyFields(t *testing.T) {
	config := AuthConfig{IsEnabled: true, LocalLogin: &LocalLoginConfig{IsEnabled: false},
		AdminUserName: schemas.NewSecretVar("old-admin"), AdminPassword: schemas.NewSecretVar("old-verifier")}
	assert.Empty(t, config.AuthenticationMethods())
}

func TestAuthConfigAuthenticationMethodsSupportLocalOIDCAndMixedModes(t *testing.T) {
	tests := []struct {
		name     string
		config   string
		expected []string
	}{
		{
			name: "local login",
			config: `{
				"is_enabled": true,
				"local_login": {
					"is_enabled": true,
					"session_ttl_seconds": 7200,
					"idle_timeout_seconds": 900,
					"allow_registration": false
				}
			}`,
			expected: []string{"local"},
		},
		{
			name: "OIDC only",
			config: `{
				"is_enabled": true,
				"oidc_providers": [{
					"id": "entra",
					"display_name": "Microsoft Entra ID",
					"issuer_url": "https://login.microsoftonline.com/tenant/v2.0",
					"client_id": "env.ENTRA_CLIENT_ID",
					"client_secret": "env.ENTRA_CLIENT_SECRET"
				}]
			}`,
			expected: []string{"oidc"},
		},
		{
			name: "mixed login",
			config: `{
				"is_enabled": true,
				"local_login": {"is_enabled": true, "allow_registration": false},
				"oidc_providers": [{
					"id": "okta",
					"display_name": "Okta",
					"issuer_url": "https://example.okta.com",
					"client_id": "env.OKTA_CLIENT_ID",
					"client_secret": "env.OKTA_CLIENT_SECRET"
				}]
			}`,
			expected: []string{"local", "oidc"},
		},
		{
			name: "named provider with claim mappings and additional audience",
			config: `{
				"is_enabled": true,
				"oidc_providers": [{
					"id": "auth0", "type": "auth0", "display_name": "Auth0",
					"issuer_url": "https://tenant.example", "client_id": "client", "client_secret": "secret",
					"allowed_audiences": ["https://api.example"],
					"claim_mappings": {"email": "profile.email", "email_verified": "profile.verified", "name": "profile.display_name"}
				}]
			}`,
			expected: []string{"oidc"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var config AuthConfig
			require.NoError(t, json.Unmarshal([]byte(tt.config), &config))
			assert.Equal(t, tt.expected, authConfigAuthenticationMethods(t, config))
			require.NoError(t, authConfigValidate(t, config))
		})
	}
}

func TestAuthConfigValidationRejectsUnsafeOrUnusableModes(t *testing.T) {
	tests := []struct {
		name          string
		config        string
		expectedError string
	}{
		{
			name: "enabled with no login method",
			config: `{
				"is_enabled": true,
				"local_login": {"is_enabled": false, "allow_registration": false}
			}`,
			expectedError: "usable login method",
		},
		{
			name: "public registration",
			config: `{
				"is_enabled": true,
				"local_login": {"is_enabled": true, "allow_registration": true}
			}`,
			expectedError: "allow_registration",
		},
		{
			name: "duplicate OIDC provider ID",
			config: `{
				"is_enabled": true,
				"oidc_providers": [
					{"id": "entra", "display_name": "Entra", "issuer_url": "https://issuer.example", "client_id": "client", "client_secret": "secret"},
					{"id": "entra", "display_name": "Entra again", "issuer_url": "https://issuer-two.example", "client_id": "client", "client_secret": "secret"}
				]
			}`,
			expectedError: "duplicate OIDC provider ID",
		},
		{
			name: "invalid allowed email domain",
			config: `{
				"is_enabled": true,
				"oidc_providers": [{"id": "entra", "display_name": "Entra", "issuer_url": "https://issuer.example", "client_id": "client", "client_secret": "secret", "allowed_email_domains": ["example.com/path"]}]
			}`,
			expectedError: "allowed_email_domains",
		},
		{
			name: "unsupported provider type",
			config: `{
				"is_enabled": true,
				"oidc_providers": [{"id": "custom", "type": "unsupported", "display_name": "Custom", "issuer_url": "https://issuer.example", "client_id": "client", "client_secret": "secret"}]
			}`,
			expectedError: "unsupported type",
		},
		{
			name: "duplicate audience",
			config: `{
				"is_enabled": true,
				"oidc_providers": [{"id": "entra", "display_name": "Entra", "issuer_url": "https://issuer.example", "client_id": "client", "client_secret": "secret", "allowed_audiences": ["api", "api"]}]
			}`,
			expectedError: "duplicate allowed_audiences",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var config AuthConfig
			require.NoError(t, json.Unmarshal([]byte(tt.config), &config))
			assert.ErrorContains(t, authConfigValidate(t, config), tt.expectedError)
		})
	}
}

func TestAuthConfigNormalizedAppliesSessionDefaultsWithoutMutatingInput(t *testing.T) {
	config := AuthConfig{
		IsEnabled: true,
		LocalLogin: &LocalLoginConfig{
			IsEnabled:         true,
			AllowRegistration: false,
		},
	}

	normalized := config.Normalized()

	require.NotNil(t, normalized.LocalLogin)
	assert.Equal(t, int(DefaultSessionTTL.Seconds()), normalized.LocalLogin.SessionTTLSeconds)
	assert.Equal(t, int(DefaultSessionIdleTimeout.Seconds()), normalized.LocalLogin.IdleTimeoutSeconds)
	assert.Zero(t, config.LocalLogin.SessionTTLSeconds, "normalization must not mutate file-owned configuration")
	assert.Zero(t, config.LocalLogin.IdleTimeoutSeconds, "normalization must not mutate file-owned configuration")
}

func TestOIDCProviderEffectiveClaimMappingsApplyPresetDefaultsAndOverrides(t *testing.T) {
	provider := OIDCProviderConfig{Type: "auth0", ClaimMappings: OIDCClaimMappings{Email: "profile.email"}}
	mapping := provider.EffectiveClaimMappings()
	assert.Equal(t, "profile.email", mapping.Email)
	assert.Equal(t, "email_verified", mapping.EmailVerified)
	assert.Equal(t, "name", mapping.Name)
	assert.Equal(t, "groups", mapping.Groups)
	assert.Equal(t, "roles", mapping.Roles)

	generic := (OIDCProviderConfig{}).EffectiveClaimMappings()
	assert.Equal(t, OIDCClaimMappings{Email: "email", EmailVerified: "email_verified", Name: "name"}, generic)
}

func TestAuthConfigRedactedNeverExposesOIDCClientSecrets(t *testing.T) {
	t.Setenv("BIFROST_OIDC_CLIENT_ID", "real-oidc-client-id")
	t.Setenv("BIFROST_OIDC_CLIENT_SECRET", "real-oidc-client-secret")
	config := &AuthConfig{
		IsEnabled: true,
		OIDCProviders: []OIDCProviderConfig{{
			ID:           "entra",
			DisplayName:  "Microsoft Entra ID",
			IssuerURL:    "https://login.microsoftonline.com/tenant/v2.0",
			ClientID:     schemas.NewSecretVar("env.BIFROST_OIDC_CLIENT_ID"),
			ClientSecret: schemas.NewSecretVar("env.BIFROST_OIDC_CLIENT_SECRET"),
			IsEnabled:    true,
		}},
	}

	redactedJSON, err := json.Marshal(config.Redacted())
	require.NoError(t, err)
	assert.NotContains(t, string(redactedJSON), "real-oidc-client-id")
	assert.NotContains(t, string(redactedJSON), "real-oidc-client-secret")
	assert.Contains(t, string(redactedJSON), "env.BIFROST_OIDC_CLIENT_ID")
	assert.Contains(t, string(redactedJSON), "env.BIFROST_OIDC_CLIENT_SECRET")
	assert.Equal(t, "real-oidc-client-secret", config.OIDCProviders[0].ClientSecret.GetValue(), "redaction must not mutate the runtime config")
}

// These reflection helpers deliberately make the contract test executable before
// the production methods exist. That gives this task a behavioral red state
// instead of treating a missing API as a passing compilation placeholder.
func authConfigAuthenticationMethods(t *testing.T, config AuthConfig) []string {
	t.Helper()
	method := reflect.ValueOf(config).MethodByName("AuthenticationMethods")
	require.True(t, method.IsValid(), "AuthConfig must expose AuthenticationMethods")
	results := method.Call(nil)
	require.Len(t, results, 1)
	methods, ok := results[0].Interface().([]string)
	require.True(t, ok, "AuthenticationMethods must return []string")
	return methods
}

func authConfigValidate(t *testing.T, config AuthConfig) error {
	t.Helper()
	method := reflect.ValueOf(config).MethodByName("Validate")
	require.True(t, method.IsValid(), "AuthConfig must expose Validate")
	results := method.Call(nil)
	require.Len(t, results, 1)
	if results[0].IsNil() {
		return nil
	}
	err, ok := results[0].Interface().(error)
	require.True(t, ok, "Validate must return an error")
	return err
}
