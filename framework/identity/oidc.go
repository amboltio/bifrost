package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/maximhq/bifrost/framework/configstore/tables"
)

const oidcTransactionTTL = 10 * time.Minute

var (
	ErrOIDCProviderUnavailable   = errors.New("OIDC provider is unavailable")
	ErrOIDCTransactionInvalid    = errors.New("OIDC login transaction is invalid")
	ErrOIDCIdentityNotLinked     = errors.New("OIDC identity is not linked")
	ErrOIDCIdentityAlreadyLinked = errors.New("OIDC identity is already linked to another user")
)

// OIDCProvider is the runtime-safe subset of the declarative provider config.
// Secrets are copied into this value only for the bounded token exchange and
// are never included in results, audit fields, or persistence rows.
type OIDCProvider struct {
	ID                   string
	DisplayName          string
	Type                 string
	IssuerURL            string
	ClientID             string
	ClientSecret         string
	Scopes               []string
	AllowedAudiences     []string
	ClaimMappings        OIDCClaimMappings
	AllowJITProvisioning bool
	AllowedEmailDomains  []string
}

// OIDCClaimMappings mirrors the declarative config without importing the
// broader configstore package into the protocol package.
type OIDCClaimMappings struct {
	Email         string
	EmailVerified string
	Name          string
	Groups        string
	Roles         string
}

// OIDCLoginStore is intentionally narrower than ConfigStore. It makes the
// protocol service usable with an isolated test store and prevents unrelated
// governance methods from becoming part of the authentication boundary.
type OIDCLoginStore interface {
	CreateOIDCTransaction(ctx context.Context, transaction *tables.TableOIDCTransaction) error
	ClaimOIDCTransaction(ctx context.Context, stateHash string, now time.Time) (*tables.TableOIDCTransaction, error)
	GetExternalIdentityByIssuerSubject(ctx context.Context, issuer, subject string) (*tables.TableExternalIdentity, error)
	TouchExternalIdentity(ctx context.Context, id string, seenAt time.Time) error
	GetUser(ctx context.Context, id string) (*tables.TableUser, error)
}

type OIDCLinkStore interface {
	LinkExternalIdentity(ctx context.Context, userID string, external *tables.TableExternalIdentity) error
}

type OIDCProvisioningStore interface {
	ProvisionOIDCIdentity(ctx context.Context, user *tables.TableUser, external *tables.TableExternalIdentity, roleID string) (*tables.TableUser, error)
}

type OIDCLoginStart struct {
	AuthorizationURL string
	ExpiresAt        time.Time
}

// OIDCProviderMetadata is the safe discovery result exposed to administrators
// during provider verification. It contains endpoints only, never credentials
// or ID-token material.
type OIDCProviderMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

type OIDCLoginResult struct {
	UserID       string
	ProviderID   string
	RedirectPath string
	Linked       bool
}

type OIDCService struct {
	store  OIDCLoginStore
	client *http.Client
	now    func() time.Time
}

func NewOIDCService(store OIDCLoginStore, client *http.Client, now func() time.Time) *OIDCService {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	} else {
		copy := *client
		client = &copy
		if client.Timeout <= 0 {
			client.Timeout = 10 * time.Second
		}
	}
	// Metadata and token endpoints must never silently redirect to another
	// origin. The issuer operator configured is the trust anchor.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if now == nil {
		now = time.Now
	}
	return &OIDCService{store: store, client: client, now: now}
}

func (s *OIDCService) Begin(ctx context.Context, provider OIDCProvider, callbackURL, redirectPath string) (*OIDCLoginStart, error) {
	return s.begin(ctx, provider, callbackURL, redirectPath, "")
}

func (s *OIDCService) VerifyProvider(ctx context.Context, provider OIDCProvider) (*OIDCProviderMetadata, error) {
	if s == nil || s.store == nil {
		return nil, ErrOIDCProviderUnavailable
	}
	if err := validateOIDCProvider(provider); err != nil {
		return nil, err
	}
	discovery, err := s.discover(ctx, provider.IssuerURL)
	if err != nil {
		return nil, err
	}
	return &OIDCProviderMetadata{
		Issuer: discovery.Issuer, AuthorizationEndpoint: discovery.AuthorizationEndpoint,
		TokenEndpoint: discovery.TokenEndpoint, JWKSURI: discovery.JWKSURI,
	}, nil
}

// BeginLink starts the same protected OIDC transaction but binds the verified
// callback to an already authenticated canonical user.
func (s *OIDCService) BeginLink(ctx context.Context, provider OIDCProvider, callbackURL, redirectPath, userID string) (*OIDCLoginStart, error) {
	return s.begin(ctx, provider, callbackURL, redirectPath, strings.TrimSpace(userID))
}

func (s *OIDCService) begin(ctx context.Context, provider OIDCProvider, callbackURL, redirectPath, linkUserID string) (*OIDCLoginStart, error) {
	if s == nil || s.store == nil {
		return nil, ErrOIDCProviderUnavailable
	}
	if err := validateOIDCProvider(provider); err != nil {
		return nil, err
	}
	if err := validateOIDCCallbackURL(callbackURL); err != nil {
		return nil, err
	}
	redirectPath, err := normalizeOIDCRedirectPath(redirectPath)
	if err != nil {
		return nil, err
	}
	discovery, err := s.discover(ctx, provider.IssuerURL)
	if err != nil {
		return nil, err
	}
	state, err := randomURLToken(32)
	if err != nil {
		return nil, fmt.Errorf("generate OIDC state: %w", err)
	}
	nonce, err := randomURLToken(32)
	if err != nil {
		return nil, fmt.Errorf("generate OIDC nonce: %w", err)
	}
	verifier, err := randomURLToken(48)
	if err != nil {
		return nil, fmt.Errorf("generate OIDC PKCE verifier: %w", err)
	}
	now := s.now().UTC()
	expiresAt := now.Add(oidcTransactionTTL)
	transaction := &tables.TableOIDCTransaction{
		ID: uuid.NewString(), StateHash: digestString(state), NonceHash: digestString(nonce),
		ProviderID: provider.ID, CodeVerifier: verifier, RedirectPath: redirectPath, ExpiresAt: expiresAt,
	}
	if linkUserID != "" {
		transaction.LinkUserID = &linkUserID
	}
	if err := s.store.CreateOIDCTransaction(ctx, transaction); err != nil {
		return nil, fmt.Errorf("persist OIDC login transaction: %w", err)
	}

	scopes := make([]string, 0, len(provider.Scopes)+1)
	seenScopes := map[string]struct{}{}
	for _, scope := range append([]string{"openid"}, provider.Scopes...) {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		if _, seen := seenScopes[scope]; seen {
			continue
		}
		seenScopes[scope] = struct{}{}
		scopes = append(scopes, scope)
	}
	params := url.Values{
		"client_id":             {provider.ClientID},
		"redirect_uri":          {callbackURL},
		"response_type":         {"code"},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {pkceChallenge(verifier)},
		"code_challenge_method": {"S256"},
	}
	authorizationURL, err := url.Parse(discovery.AuthorizationEndpoint)
	if err != nil {
		return nil, ErrOIDCProviderUnavailable
	}
	authorizationURL.RawQuery = params.Encode()
	return &OIDCLoginStart{AuthorizationURL: authorizationURL.String(), ExpiresAt: expiresAt}, nil
}

func (s *OIDCService) Complete(ctx context.Context, provider OIDCProvider, callbackURL, state, code string) (*OIDCLoginResult, error) {
	if s == nil || s.store == nil {
		return nil, ErrOIDCProviderUnavailable
	}
	if err := validateOIDCProvider(provider); err != nil {
		return nil, err
	}
	if err := validateOIDCCallbackURL(callbackURL); err != nil {
		return nil, err
	}
	state = strings.TrimSpace(state)
	code = strings.TrimSpace(code)
	if state == "" || code == "" {
		return nil, ErrOIDCTransactionInvalid
	}
	transaction, err := s.store.ClaimOIDCTransaction(ctx, digestString(state), s.now().UTC())
	if err != nil {
		return nil, fmt.Errorf("claim OIDC login transaction: %w", err)
	}
	if transaction == nil || transaction.ProviderID != provider.ID {
		return nil, ErrOIDCTransactionInvalid
	}
	discovery, err := s.discover(ctx, provider.IssuerURL)
	if err != nil {
		return nil, err
	}
	idToken, err := s.exchangeCode(ctx, provider, discovery.TokenEndpoint, callbackURL, code, transaction.CodeVerifier)
	if err != nil {
		return nil, err
	}
	claims, err := s.verifyIDToken(ctx, idToken, discovery, provider)
	if err != nil {
		return nil, err
	}
	if !emailDomainAllowed(claims.Email, provider.AllowedEmailDomains) {
		return nil, ErrOIDCIdentityNotLinked
	}
	nonceDigest := digestString(claims.Nonce)
	if subtle.ConstantTimeCompare([]byte(nonceDigest), []byte(transaction.NonceHash)) != 1 {
		return nil, ErrOIDCTransactionInvalid
	}
	external, err := s.store.GetExternalIdentityByIssuerSubject(ctx, discovery.Issuer, claims.Subject)
	if err != nil {
		return nil, err
	}
	var user *tables.TableUser
	if transaction.LinkUserID != nil && strings.TrimSpace(*transaction.LinkUserID) != "" {
		linker, ok := s.store.(OIDCLinkStore)
		if !ok {
			return nil, ErrOIDCIdentityNotLinked
		}
		userID := strings.TrimSpace(*transaction.LinkUserID)
		user, err = s.store.GetUser(ctx, userID)
		if err != nil {
			return nil, err
		}
		if user == nil || user.Status != tables.UserStatusActive {
			return nil, ErrOIDCIdentityNotLinked
		}
		if external != nil && external.UserID != userID {
			return nil, ErrOIDCIdentityAlreadyLinked
		}
		if external == nil {
			external = &tables.TableExternalIdentity{UserID: userID, ProviderID: provider.ID, Issuer: discovery.Issuer, Subject: claims.Subject, IsActive: true}
		}
		if err := linker.LinkExternalIdentity(ctx, userID, external); err != nil {
			return nil, err
		}
		if err := s.store.TouchExternalIdentity(ctx, external.ID, s.now().UTC()); err != nil {
			return nil, err
		}
		return &OIDCLoginResult{UserID: user.ID, ProviderID: provider.ID, RedirectPath: transaction.RedirectPath, Linked: true}, nil
	}
	if external == nil {
		if !provider.AllowJITProvisioning || !claims.EmailVerified || strings.TrimSpace(claims.Email) == "" {
			return nil, ErrOIDCIdentityNotLinked
		}
		provisioner, ok := s.store.(OIDCProvisioningStore)
		if !ok {
			return nil, ErrOIDCIdentityNotLinked
		}
		user = &tables.TableUser{Email: stringPointer(claims.Email), DisplayName: claims.Name, Status: tables.UserStatusActive, EmailVerified: true}
		if strings.TrimSpace(user.DisplayName) == "" {
			user.DisplayName = claims.Email
		}
		external = &tables.TableExternalIdentity{UserID: user.ID, ProviderID: provider.ID, Issuer: discovery.Issuer, Subject: claims.Subject, IsActive: true}
		user, err = provisioner.ProvisionOIDCIdentity(ctx, user, external, "viewer")
		if err != nil {
			return nil, err
		}
	} else if !external.IsActive || external.ProviderID != provider.ID {
		return nil, ErrOIDCIdentityNotLinked
	}
	if user == nil {
		user, err = s.store.GetUser(ctx, external.UserID)
		if err != nil {
			return nil, err
		}
	}
	if user == nil || user.Status != tables.UserStatusActive {
		return nil, ErrOIDCIdentityNotLinked
	}
	if err := s.store.TouchExternalIdentity(ctx, external.ID, s.now().UTC()); err != nil {
		return nil, err
	}
	return &OIDCLoginResult{UserID: user.ID, ProviderID: provider.ID, RedirectPath: transaction.RedirectPath}, nil
}

type oidcDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

func (s *OIDCService) discover(ctx context.Context, issuer string) (*oidcDiscovery, error) {
	issuer = canonicalOIDCIssuer(issuer)
	discoveryURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	var discovery oidcDiscovery
	if err := s.getJSON(ctx, discoveryURL, &discovery); err != nil {
		return nil, ErrOIDCProviderUnavailable
	}
	if canonicalOIDCIssuer(discovery.Issuer) != issuer || !validOIDCEndpoint(discovery.AuthorizationEndpoint) || !validOIDCEndpoint(discovery.TokenEndpoint) || !validOIDCEndpoint(discovery.JWKSURI) {
		return nil, ErrOIDCProviderUnavailable
	}
	discovery.Issuer = canonicalOIDCIssuer(discovery.Issuer)
	return &discovery, nil
}

func (s *OIDCService) exchangeCode(ctx context.Context, provider OIDCProvider, tokenEndpoint, callbackURL, code, verifier string) (string, error) {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {callbackURL}, "client_id": {provider.ClientID}, "code_verifier": {verifier}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", ErrOIDCProviderUnavailable
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(provider.ClientID, provider.ClientSecret)
	resp, err := s.client.Do(req)
	if err != nil {
		return "", ErrOIDCProviderUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return "", ErrOIDCProviderUnavailable
	}
	var payload struct {
		IDToken string `json:"id_token"`
	}
	if err := decodeLimitedJSON(resp, &payload); err != nil || strings.TrimSpace(payload.IDToken) == "" {
		return "", ErrOIDCProviderUnavailable
	}
	return payload.IDToken, nil
}

type oidcIDTokenClaims struct {
	jwt.RegisteredClaims
	Nonce         string `json:"nonce"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`
	raw           map[string]any
}

func (c *oidcIDTokenClaims) UnmarshalJSON(data []byte) error {
	type alias oidcIDTokenClaims
	var parsed alias
	if err := json.Unmarshal(data, &parsed); err != nil {
		return err
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*c = oidcIDTokenClaims(parsed)
	c.raw = raw
	return nil
}

func (c *oidcIDTokenClaims) applyClaimMappings(mapping OIDCClaimMappings) {
	if c == nil {
		return
	}
	if value, ok := claimValue(c.raw, mapping.Email); ok {
		if email, ok := value.(string); ok {
			c.Email = strings.TrimSpace(email)
		}
	}
	if value, ok := claimValue(c.raw, mapping.EmailVerified); ok {
		switch verified := value.(type) {
		case bool:
			c.EmailVerified = verified
		case string:
			c.EmailVerified = strings.EqualFold(strings.TrimSpace(verified), "true")
		}
	}
	if value, ok := claimValue(c.raw, mapping.Name); ok {
		if name, ok := value.(string); ok {
			c.Name = strings.TrimSpace(name)
		}
	}
}

func claimValue(raw map[string]any, path string) (any, bool) {
	path = strings.TrimSpace(path)
	if path == "" || len(raw) == 0 {
		return nil, false
	}
	var current any = raw
	for _, part := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func (s *OIDCService) verifyIDToken(ctx context.Context, raw string, discovery *oidcDiscovery, provider OIDCProvider) (*oidcIDTokenClaims, error) {
	var jwks struct {
		Keys []oidcJWK `json:"keys"`
	}
	if err := s.getJSON(ctx, discovery.JWKSURI, &jwks); err != nil {
		return nil, ErrOIDCProviderUnavailable
	}
	claims := &oidcIDTokenClaims{}
	audiences := make([]string, 0, len(provider.AllowedAudiences)+1)
	seenAudiences := make(map[string]struct{}, len(provider.AllowedAudiences)+1)
	for _, audience := range append(provider.AllowedAudiences, provider.ClientID) {
		audience = strings.TrimSpace(audience)
		if audience == "" {
			continue
		}
		if _, exists := seenAudiences[audience]; exists {
			continue
		}
		seenAudiences[audience] = struct{}{}
		audiences = append(audiences, audience)
	}
	token, err := jwt.ParseWithClaims(raw, claims, func(parsed *jwt.Token) (any, error) {
		kid, _ := parsed.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("OIDC token has no key ID")
		}
		for _, key := range jwks.Keys {
			if key.KID != kid || (key.Use != "" && key.Use != "sig") || (key.Alg != "" && key.Alg != parsed.Method.Alg()) {
				continue
			}
			publicKey, keyErr := key.publicKey(parsed.Method.Alg())
			if keyErr != nil {
				return nil, keyErr
			}
			return publicKey, nil
		}
		return nil, fmt.Errorf("OIDC key not found")
	}, jwt.WithIssuer(discovery.Issuer), jwt.WithAudience(audiences...), jwt.WithExpirationRequired(), jwt.WithValidMethods(oidcJWTAlgorithms))
	if err != nil || token == nil || !token.Valid || claims.Subject == "" || claims.Nonce == "" || claims.IssuedAt == nil {
		return nil, ErrOIDCTransactionInvalid
	}
	claims.applyClaimMappings(provider.ClaimMappings)
	return claims, nil
}

var oidcJWTAlgorithms = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}

type oidcJWK struct {
	KTY string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	KID string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (key oidcJWK) publicKey(algorithm string) (any, error) {
	decode := func(value string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(value) }
	switch key.KTY {
	case "RSA":
		if !strings.HasPrefix(algorithm, "RS") && !strings.HasPrefix(algorithm, "PS") {
			return nil, fmt.Errorf("OIDC RSA key used with %s", algorithm)
		}
		n, err := decode(key.N)
		if err != nil || len(n) == 0 {
			return nil, fmt.Errorf("invalid OIDC RSA modulus")
		}
		e, err := decode(key.E)
		if err != nil || len(e) == 0 {
			return nil, fmt.Errorf("invalid OIDC RSA exponent")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
	case "EC":
		if !strings.HasPrefix(algorithm, "ES") {
			return nil, fmt.Errorf("OIDC EC key used with %s", algorithm)
		}
		var curve elliptic.Curve
		switch key.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported OIDC EC curve")
		}
		x, err := decode(key.X)
		if err != nil {
			return nil, fmt.Errorf("invalid OIDC EC x coordinate")
		}
		y, err := decode(key.Y)
		if err != nil {
			return nil, fmt.Errorf("invalid OIDC EC y coordinate")
		}
		public := &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !curve.IsOnCurve(public.X, public.Y) {
			return nil, fmt.Errorf("OIDC EC point is not on curve")
		}
		return public, nil
	case "OKP":
		if algorithm != "EdDSA" || key.Crv != "Ed25519" {
			return nil, fmt.Errorf("unsupported OIDC OKP key")
		}
		x, err := decode(key.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid OIDC Ed25519 key")
		}
		return ed25519.PublicKey(x), nil
	default:
		return nil, fmt.Errorf("unsupported OIDC key type")
	}
}

func (s *OIDCService) getJSON(ctx context.Context, endpoint string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("OIDC endpoint returned status %d", resp.StatusCode)
	}
	return decodeLimitedJSON(resp, out)
}

func decodeLimitedJSON(resp *http.Response, out any) error {
	const maxOIDCResponseBytes = 2 << 20
	decoder := json.NewDecoder(io.LimitReader(resp.Body, maxOIDCResponseBytes))
	return decoder.Decode(out)
}

func validateOIDCProvider(provider OIDCProvider) error {
	if strings.TrimSpace(provider.ID) == "" || strings.TrimSpace(provider.ClientID) == "" || strings.TrimSpace(provider.ClientSecret) == "" {
		return ErrOIDCProviderUnavailable
	}
	issuer := canonicalOIDCIssuer(provider.IssuerURL)
	if issuer == "" || !validOIDCEndpoint(issuer) {
		return ErrOIDCProviderUnavailable
	}
	return nil
}

func validateOIDCCallbackURL(callback string) error {
	parsed, err := url.Parse(callback)
	if err != nil || parsed.User != nil || parsed.Host == "" || parsed.Path == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return ErrOIDCProviderUnavailable
	}
	if parsed.Scheme == "https" {
		return nil
	}
	if parsed.Scheme == "http" && (parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "::1") {
		return nil
	}
	return ErrOIDCProviderUnavailable
}

func normalizeOIDCRedirectPath(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "/", nil
	}
	if strings.Contains(value, "\\") || !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") {
		return "", ErrOIDCProviderUnavailable
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.IsAbs() || parsed.Host != "" {
		return "", ErrOIDCProviderUnavailable
	}
	return value, nil
}

func canonicalOIDCIssuer(value string) string {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return ""
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	return strings.TrimRight(parsed.String(), "/")
}

func validOIDCEndpoint(value string) bool {
	parsed, err := url.Parse(strings.TrimSpace(value))
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == ""
}

func randomURLToken(size int) (string, error) {
	bytes := make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func digestString(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func pkceChallenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func stringPointer(value string) *string {
	return &value
}

func emailDomainAllowed(email string, allowedDomains []string) bool {
	if len(allowedDomains) == 0 {
		return true
	}
	parts := strings.Split(strings.ToLower(strings.TrimSpace(email)), "@")
	if len(parts) != 2 || parts[1] == "" {
		return false
	}
	domain := parts[1]
	for _, allowed := range allowedDomains {
		allowed = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(allowed)), "@")
		if allowed != "" && domain == allowed {
			return true
		}
	}
	return false
}
