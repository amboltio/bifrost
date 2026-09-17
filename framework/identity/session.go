package identity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/maximhq/bifrost/framework/configstore/tables"
)

// ErrUnauthenticated deliberately gives callers one generic result for a
// missing, expired, disabled, or revoked session.
var ErrUnauthenticated = errors.New("unauthenticated")

// SessionPolicy defines the absolute and inactivity lifetime of new sessions.
type SessionPolicy struct {
	AbsoluteTTL time.Duration
	IdleTimeout time.Duration
}

// IdentitySessionStore is the minimum storage contract for trusted request
// authentication. RDBConfigStore implements it; tests use a small in-memory
// fake rather than the broad configuration-store interface.
type IdentitySessionStore interface {
	GetUser(ctx context.Context, id string) (*tables.TableUser, error)
	GetSession(ctx context.Context, token string) (*tables.SessionsTable, error)
	CreateSession(ctx context.Context, session *tables.SessionsTable) error
	TouchIdentitySession(ctx context.Context, id int, lastSeenAt, idleExpiresAt time.Time) error
	RevokeIdentitySession(ctx context.Context, id int, revokedAt time.Time) error
}

// SessionService creates and authenticates identity-bound dashboard sessions.
type SessionService struct {
	store  IdentitySessionStore
	policy SessionPolicy
	now    func() time.Time
}

// NewSessionService applies safe defaults when the configuration omitted them.
func NewSessionService(store IdentitySessionStore, policy SessionPolicy, now func() time.Time) *SessionService {
	if policy.AbsoluteTTL <= 0 {
		policy.AbsoluteTTL = 12 * time.Hour
	}
	if policy.IdleTimeout <= 0 {
		policy.IdleTimeout = 30 * time.Minute
	}
	if now == nil {
		now = time.Now
	}
	return &SessionService{store: store, policy: policy, now: now}
}

// IssueSession returns a raw token only to the caller. The persistence hook
// hashes and encrypts it before storage, while expiry/version fields make each
// request independently revocable.
func (s *SessionService) IssueSession(ctx context.Context, userID, method, providerID string) (string, time.Time, error) {
	if s.store == nil || strings.TrimSpace(userID) == "" || strings.TrimSpace(method) == "" {
		return "", time.Time{}, fmt.Errorf("session user ID and method are required")
	}
	user, err := s.store.GetUser(ctx, userID)
	if err != nil {
		return "", time.Time{}, err
	}
	if user == nil || user.Status != tables.UserStatusActive {
		return "", time.Time{}, ErrUnauthenticated
	}
	rawBytes := make([]byte, 32)
	if _, err := rand.Read(rawBytes); err != nil {
		return "", time.Time{}, fmt.Errorf("generate session token: %w", err)
	}
	now := s.now().UTC()
	absoluteExpiry := now.Add(s.policy.AbsoluteTTL)
	idleExpiry := now.Add(s.policy.IdleTimeout)
	var provider *string
	if providerID = strings.TrimSpace(providerID); providerID != "" {
		provider = &providerID
	}
	rawToken := base64.RawURLEncoding.EncodeToString(rawBytes)
	session := &tables.SessionsTable{
		Token: rawToken, ExpiresAt: absoluteExpiry,
		UserID: &user.ID, AuthMethod: method, ProviderID: provider, LastSeenAt: &now,
		AbsoluteExpiresAt: &absoluteExpiry, IdleExpiresAt: &idleExpiry, AuthVersion: user.AuthVersion,
	}
	if err := s.store.CreateSession(ctx, session); err != nil {
		return "", time.Time{}, err
	}
	return rawToken, absoluteExpiry, nil
}

// AuthenticateSession returns a canonical principal only when the durable
// session and user versions still agree. A mismatch revokes that session so a
// stale token cannot become valid again if a version later changes back.
func (s *SessionService) AuthenticateSession(ctx context.Context, token string) (Principal, error) {
	if s.store == nil || strings.TrimSpace(token) == "" {
		return Principal{}, ErrUnauthenticated
	}
	now := s.now().UTC()
	session, err := s.store.GetSession(ctx, token)
	if err != nil || session == nil || session.UserID == nil || !session.IsActiveAt(now) {
		return Principal{}, ErrUnauthenticated
	}
	user, err := s.store.GetUser(ctx, *session.UserID)
	if err != nil || user == nil || user.Status != tables.UserStatusActive || user.AuthVersion != session.AuthVersion {
		_ = s.store.RevokeIdentitySession(ctx, session.ID, now)
		return Principal{}, ErrUnauthenticated
	}
	idleExpiry := now.Add(s.policy.IdleTimeout)
	if err := s.store.TouchIdentitySession(ctx, session.ID, now, idleExpiry); err != nil {
		return Principal{}, ErrUnauthenticated
	}
	principal := Principal{UserID: user.ID, SessionID: session.ID, AuthMethod: session.AuthMethod, AuthVersion: user.AuthVersion}
	if session.ProviderID != nil {
		principal.ProviderID = *session.ProviderID
	}
	return principal, nil
}
