package configstore

import (
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

const (
	// DefaultSessionTTL is the maximum lifetime assigned to a local-login
	// session when the configuration omits session_ttl_seconds.
	DefaultSessionTTL = 12 * time.Hour
	// DefaultSessionIdleTimeout is the inactivity timeout assigned to a
	// local-login session when the configuration omits idle_timeout_seconds.
	DefaultSessionIdleTimeout = 30 * time.Minute
)

// IdentityFeatureCapabilities lets the dashboard distinguish a recognized
// configuration contract from a backend feature that is ready to use. The
// values are deliberately conservative: a UI must not present a management
// section until its authorization and persistence paths are implemented.
type IdentityFeatureCapabilities struct {
	LocalUsers     bool `json:"local_users"`
	OIDCLogin      bool `json:"oidc_login"`
	Organizations  bool `json:"organizations"`
	Roles          bool `json:"roles"`
	AccessProfiles bool `json:"access_profiles"`
	Projects       bool `json:"projects"`
	UserAnalytics  bool `json:"user_analytics"`
}

// ImplementedIdentityFeatureCapabilities is the public feature gate for
// identity/governance management UI. Each value moves to true only with its
// protected backend vertical slice, never merely because schema fields exist.
func ImplementedIdentityFeatureCapabilities() IdentityFeatureCapabilities {
	return IdentityFeatureCapabilities{}
}

// LocalLoginConfig controls email/password sign-in. Account creation is
// intentionally disabled in OSS configuration: administrators provision users
// through the management API once identity persistence is available.
type LocalLoginConfig struct {
	IsEnabled          bool `json:"is_enabled"`
	SessionTTLSeconds  int  `json:"session_ttl_seconds,omitempty"`
	IdleTimeoutSeconds int  `json:"idle_timeout_seconds,omitempty"`
	AllowRegistration  bool `json:"allow_registration"`
}

// OIDCProviderConfig is the declarative portion of one OpenID Connect login
// provider. Runtime discovery, PKCE transactions and token verification are
// implemented separately; this contract purposefully stores no token material.
type OIDCProviderConfig struct {
	ID           string             `json:"id"`
	DisplayName  string             `json:"display_name"`
	IssuerURL    string             `json:"issuer_url"`
	ClientID     *schemas.SecretVar `json:"client_id"`
	ClientSecret *schemas.SecretVar `json:"client_secret"`
	Scopes       []string           `json:"scopes,omitempty"`
	IsEnabled    bool               `json:"is_enabled"`
}

// UnmarshalJSON defaults a declared provider to enabled. This preserves the
// concise provider entries accepted by the initial configuration contract while
// still letting an operator retain a disabled provider for later reactivation.
func (p *OIDCProviderConfig) UnmarshalJSON(data []byte) error {
	type oidcProviderConfigAlias OIDCProviderConfig
	type oidcProviderConfigInput struct {
		*oidcProviderConfigAlias
		IsEnabled *bool `json:"is_enabled"`
	}

	alias := oidcProviderConfigAlias{}
	input := oidcProviderConfigInput{oidcProviderConfigAlias: &alias}
	if err := json.Unmarshal(data, &input); err != nil {
		return err
	}
	if input.IsEnabled == nil {
		alias.IsEnabled = true
	} else {
		alias.IsEnabled = *input.IsEnabled
	}
	*p = OIDCProviderConfig(alias)
	return nil
}

// AuthConfig represents dashboard authentication configuration. The legacy
// admin fields remain during the additive migration to canonical users; new
// deployments should use local_login and/or oidc_providers.
type AuthConfig struct {
	AdminUserName *schemas.SecretVar   `json:"admin_username,omitempty"`
	AdminPassword *schemas.SecretVar   `json:"admin_password,omitempty"`
	IsEnabled     bool                 `json:"is_enabled"`
	LocalLogin    *LocalLoginConfig    `json:"local_login,omitempty"`
	OIDCProviders []OIDCProviderConfig `json:"oidc_providers,omitempty"`
}

// AuthenticationMethods returns the public login method categories currently
// usable by this configuration. It intentionally exposes categories rather
// than provider details; callers use EnabledOIDCProviders for the latter.
func (c AuthConfig) AuthenticationMethods() []string {
	if !c.IsEnabled {
		return nil
	}

	methods := make([]string, 0, 2)
	if c.localLoginEnabled() {
		methods = append(methods, "local")
	}
	if len(c.EnabledOIDCProviders()) > 0 {
		methods = append(methods, "oidc")
	}
	return methods
}

// EnabledOIDCProviders returns a shallow copy of enabled provider metadata so
// callers cannot alter the configured slice while iterating over it.
func (c AuthConfig) EnabledOIDCProviders() []OIDCProviderConfig {
	providers := make([]OIDCProviderConfig, 0, len(c.OIDCProviders))
	for _, provider := range c.OIDCProviders {
		if provider.IsEnabled {
			providers = append(providers, provider)
		}
	}
	return providers
}

// Normalized applies secure session defaults without mutating the source
// configuration. Validation is deliberately separate so callers can surface a
// precise configuration error before relying on the defaults.
func (c AuthConfig) Normalized() AuthConfig {
	normalized := c
	if c.LocalLogin == nil {
		return normalized
	}

	localLogin := *c.LocalLogin
	if localLogin.SessionTTLSeconds == 0 {
		localLogin.SessionTTLSeconds = int(DefaultSessionTTL / time.Second)
	}
	if localLogin.IdleTimeoutSeconds == 0 {
		localLogin.IdleTimeoutSeconds = int(DefaultSessionIdleTimeout / time.Second)
	}
	normalized.LocalLogin = &localLogin
	return normalized
}

// Equivalent reports whether two declarations have the same authentication
// behavior after applying defaults. It supports the deprecated top-level alias
// during configuration loading without silently choosing one conflicting block.
func (c AuthConfig) Equivalent(other AuthConfig) bool {
	return reflect.DeepEqual(c.Normalized(), other.Normalized())
}

// Validate checks the declarative authentication contract before it reaches a
// login handler. It does not resolve external secrets or perform OIDC network
// discovery; those operations have their own bounded runtime checks.
func (c AuthConfig) Validate() error {
	if c.LocalLogin != nil {
		if c.LocalLogin.AllowRegistration {
			return fmt.Errorf("auth_config.local_login.allow_registration must be false")
		}
		if c.LocalLogin.SessionTTLSeconds < 0 {
			return fmt.Errorf("auth_config.local_login.session_ttl_seconds must be positive")
		}
		if c.LocalLogin.IdleTimeoutSeconds < 0 {
			return fmt.Errorf("auth_config.local_login.idle_timeout_seconds must be positive")
		}
		normalized := c.Normalized().LocalLogin
		if normalized.IdleTimeoutSeconds > normalized.SessionTTLSeconds {
			return fmt.Errorf("auth_config.local_login.idle_timeout_seconds cannot exceed session_ttl_seconds")
		}
	}

	providerIDs := make(map[string]struct{}, len(c.OIDCProviders))
	for _, provider := range c.OIDCProviders {
		id := strings.TrimSpace(provider.ID)
		if id == "" {
			return fmt.Errorf("auth_config.oidc_providers entries require an ID")
		}
		if _, exists := providerIDs[id]; exists {
			return fmt.Errorf("auth_config has duplicate OIDC provider ID %q", id)
		}
		providerIDs[id] = struct{}{}
		if !provider.IsEnabled {
			continue
		}
		if strings.TrimSpace(provider.DisplayName) == "" {
			return fmt.Errorf("auth_config.oidc_providers[%q] requires display_name", id)
		}
		issuerURL, err := url.ParseRequestURI(provider.IssuerURL)
		if err != nil || issuerURL.Scheme != "https" || issuerURL.Host == "" {
			return fmt.Errorf("auth_config.oidc_providers[%q] requires an HTTPS issuer_url", id)
		}
		if !hasConfiguredSecret(provider.ClientID) {
			return fmt.Errorf("auth_config.oidc_providers[%q] requires client_id", id)
		}
		if !hasConfiguredSecret(provider.ClientSecret) {
			return fmt.Errorf("auth_config.oidc_providers[%q] requires client_secret", id)
		}
	}

	if c.IsEnabled && len(c.AuthenticationMethods()) == 0 {
		return fmt.Errorf("auth_config is enabled but has no usable login method")
	}
	return nil
}

func (c AuthConfig) localLoginEnabled() bool {
	if c.LocalLogin != nil && c.LocalLogin.IsEnabled {
		return true
	}
	return hasConfiguredSecret(c.AdminUserName) && hasConfiguredSecret(c.AdminPassword)
}

func hasConfiguredSecret(value *schemas.SecretVar) bool {
	return value != nil && (strings.TrimSpace(value.GetValue()) != "" || strings.TrimSpace(value.GetRawRef()) != "")
}

// Redacted returns a copy safe to serialize through management APIs. The client
// secret is always masked; environment and vault references are preserved so an
// operator can understand configuration provenance without receiving values.
func (c *AuthConfig) Redacted() *AuthConfig {
	if c == nil {
		return nil
	}
	redacted := *c
	redacted.AdminUserName = c.AdminUserName.RedactedIfSecret()
	redacted.AdminPassword = c.AdminPassword.FullyRedacted()
	redacted.OIDCProviders = make([]OIDCProviderConfig, len(c.OIDCProviders))
	for i, provider := range c.OIDCProviders {
		redacted.OIDCProviders[i] = provider
		redacted.OIDCProviders[i].ClientID = provider.ClientID.RedactedIfSecret()
		redacted.OIDCProviders[i].ClientSecret = provider.ClientSecret.FullyRedacted()
	}
	return &redacted
}
