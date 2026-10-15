package identity

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type sessionStoreStub struct {
	user     *tables.TableUser
	session  *tables.SessionsTable
	sessions []*tables.SessionsTable
}

func newSessionStoreStub(user *tables.TableUser) *sessionStoreStub {
	return &sessionStoreStub{user: user}
}

func (s *sessionStoreStub) GetUser(context.Context, string) (*tables.TableUser, error) {
	return s.user, nil
}

func (s *sessionStoreStub) GetSession(_ context.Context, token string) (*tables.SessionsTable, error) {
	for _, session := range s.sessions {
		if session.Token == token {
			return session, nil
		}
	}
	return nil, nil
}

func (s *sessionStoreStub) CreateSession(_ context.Context, session *tables.SessionsTable) error {
	session.ID = len(s.sessions) + 1
	s.session = session
	s.sessions = append(s.sessions, session)
	return nil
}

func (s *sessionStoreStub) TouchIdentitySession(_ context.Context, id int, lastSeenAt, idleExpiresAt time.Time) error {
	for _, session := range s.sessions {
		if session.ID == id {
			session.LastSeenAt = &lastSeenAt
			session.IdleExpiresAt = &idleExpiresAt
			return nil
		}
	}
	return errors.New("session not found")
}

func (s *sessionStoreStub) RevokeIdentitySession(_ context.Context, id int, revokedAt time.Time) error {
	for _, session := range s.sessions {
		if session.ID == id {
			session.RevokedAt = &revokedAt
			return nil
		}
	}
	return errors.New("session not found")
}

func (s *sessionStoreStub) RevokeUserIdentitySession(_ context.Context, userID string, id int, revokedAt time.Time) error {
	for _, session := range s.sessions {
		if session.ID == id && session.UserID != nil && *session.UserID == userID && session.RevokedAt == nil {
			session.RevokedAt = &revokedAt
			return nil
		}
	}
	return errors.New("session not found")
}

func (s *sessionStoreStub) ListUserIdentitySessions(_ context.Context, userID string) ([]tables.SessionsTable, error) {
	var sessions []tables.SessionsTable
	for _, session := range s.sessions {
		if session.UserID != nil && *session.UserID == userID {
			sessions = append(sessions, *session)
		}
	}
	return sessions, nil
}

func (s *sessionStoreStub) RevokeUserIdentitySessions(_ context.Context, userID string, revokedAt time.Time) (int64, error) {
	var count int64
	for _, session := range s.sessions {
		if session.UserID != nil && *session.UserID == userID && session.RevokedAt == nil {
			session.RevokedAt = &revokedAt
			count++
		}
	}
	return count, nil
}

func TestSessionServiceIssuesAndAuthenticatesCanonicalPrincipal(t *testing.T) {
	now := time.Date(2026, time.September, 17, 16, 0, 0, 0, time.UTC)
	store := newSessionStoreStub(&tables.TableUser{ID: "user-1", Status: tables.UserStatusActive, AuthVersion: 4})
	service := NewSessionService(store, SessionPolicy{AbsoluteTTL: time.Hour, IdleTimeout: 10 * time.Minute}, func() time.Time { return now })

	raw, expiresAt, err := service.IssueSession(context.Background(), "user-1", "local", "")
	require.NoError(t, err)
	assert.NotEmpty(t, raw)
	assert.Equal(t, now.Add(time.Hour), expiresAt)
	require.NotNil(t, store.session.UserID)
	assert.Equal(t, "user-1", *store.session.UserID)
	assert.Equal(t, uint64(4), store.session.AuthVersion)

	principal, err := service.AuthenticateSession(context.Background(), raw)
	require.NoError(t, err)
	assert.Equal(t, "user-1", principal.UserID)
	assert.Equal(t, store.session.ID, principal.SessionID)
	assert.Equal(t, "local", principal.AuthMethod)
	assert.Equal(t, uint64(4), principal.AuthVersion)
}

func TestSessionServiceRejectsDisabledOrVersionMismatchedUser(t *testing.T) {
	now := time.Date(2026, time.September, 17, 16, 0, 0, 0, time.UTC)
	store := newSessionStoreStub(&tables.TableUser{ID: "user-1", Status: tables.UserStatusActive, AuthVersion: 2})
	service := NewSessionService(store, SessionPolicy{AbsoluteTTL: time.Hour, IdleTimeout: time.Minute}, func() time.Time { return now })
	raw, _, err := service.IssueSession(context.Background(), "user-1", "local", "")
	require.NoError(t, err)

	store.user.AuthVersion++
	_, err = service.AuthenticateSession(context.Background(), raw)
	require.ErrorIs(t, err, ErrUnauthenticated)
	require.NotNil(t, store.session.RevokedAt)
}

func TestSessionServiceListsSafeMetadataAndRevokesSessions(t *testing.T) {
	now := time.Date(2026, time.September, 17, 16, 0, 0, 0, time.UTC)
	store := newSessionStoreStub(&tables.TableUser{ID: "user-1", Status: tables.UserStatusActive, AuthVersion: 2})
	service := NewSessionService(store, SessionPolicy{AbsoluteTTL: time.Hour, IdleTimeout: time.Minute}, func() time.Time { return now })

	raw, _, err := service.IssueSession(context.Background(), "user-1", "local", "provider-1")
	require.NoError(t, err)

	sessions, err := service.ListUserSessions(context.Background(), "user-1")
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	assert.Equal(t, 1, sessions[0].ID)
	assert.Equal(t, "local", sessions[0].AuthMethod)
	assert.Equal(t, "provider-1", sessions[0].ProviderID)
	assert.Equal(t, now.Add(time.Hour), sessions[0].ExpiresAt)
	assert.NotContains(t, fmt.Sprintf("%+v", sessions[0]), raw)

	require.NoError(t, service.RevokeSession(context.Background(), 1, "logout"))
	_, err = service.AuthenticateSession(context.Background(), raw)
	require.ErrorIs(t, err, ErrUnauthenticated)

	_, _, err = service.IssueSession(context.Background(), "user-1", "local", "")
	require.NoError(t, err)
	require.NoError(t, service.RevokeUserSession(context.Background(), "user-1", 2, "self_service"))
	require.NoError(t, service.RevokeUserSessions(context.Background(), "user-1", "logout_all"))
}
