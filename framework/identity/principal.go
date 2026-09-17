package identity

// Principal is the small immutable authentication result placed on a trusted
// request context. It contains no token, verifier, profile claims, or mutable
// authorization data; authorization resolves grants separately per request.
type Principal struct {
	UserID      string
	SessionID   int
	AuthMethod  string
	ProviderID  string
	AuthVersion uint64
}
