package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type sessionStoreStub struct {
	user    *tables.TableUser
	session *tables.SessionsTable
}

func newSessionStoreStub(user *tables.TableUser) *sessionStoreStub {
	return &sessionStoreStub{user: user}
}

func (s *sessionStoreStub) GetUser(context.Context, string) (*tables.TableUser, error) {
	return s.user, nil
}

func (s *sessionStoreStub) GetSession(_ context.Context, token string) (*tables.SessionsTable, error) {
	if s.session == nil || s.session.Token != token {
		return nil, nil
	}
	return s.session, nil
}

func (s *sessionStoreStub) CreateSession(_ context.Context, session *tables.SessionsTable) error {
	if s.session != nil {
		return errors.New("unexpected second session")
	}
	session.ID = 1
	s.session = session
	return nil
}

func (s *sessionStoreStub) TouchIdentitySession(_ context.Context, id int, lastSeenAt, idleExpiresAt time.Time) error {
	if s.session == nil || s.session.ID != id {
		return errors.New("session not found")
	}
	s.session.LastSeenAt = &lastSeenAt
	s.session.IdleExpiresAt = &idleExpiresAt
	return nil
}

func (s *sessionStoreStub) RevokeIdentitySession(_ context.Context, id int, revokedAt time.Time) error {
	if s.session == nil || s.session.ID != id {
		return errors.New("session not found")
	}
	s.session.RevokedAt = &revokedAt
	return nil
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
