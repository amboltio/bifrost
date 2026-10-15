package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

type localAuthenticationStoreStub struct {
	user        *tables.TableUser
	credentials map[string]*tables.TableCredential
	changed     bool
}

func (s *localAuthenticationStoreStub) GetUserByNormalizedEmail(_ context.Context, email string) (*tables.TableUser, error) {
	if s.user != nil && s.user.NormalizedEmail != nil && *s.user.NormalizedEmail == tables.NormalizeEmail(email) {
		return s.user, nil
	}
	return nil, nil
}

func (s *localAuthenticationStoreStub) GetUserByLegacyUsername(_ context.Context, username string) (*tables.TableUser, error) {
	if s.user != nil && s.user.LegacyUsername != nil && *s.user.LegacyUsername == username {
		return s.user, nil
	}
	return nil, nil
}

func (s *localAuthenticationStoreStub) GetCredentialByUserIDAndKind(_ context.Context, userID, kind string) (*tables.TableCredential, error) {
	credential := s.credentials[kind]
	if credential == nil || credential.UserID != userID {
		return nil, nil
	}
	return credential, nil
}

func (s *localAuthenticationStoreStub) UpgradeLocalPasswordCredential(_ context.Context, userID, credentialID string, expectedVersion uint64, newHash string) error {
	credential := s.credentials[tables.CredentialKindLegacyPassword]
	if credential == nil || credential.UserID != userID || credential.ID != credentialID || credential.Version != expectedVersion || !credential.IsActive {
		return errors.New("credential changed")
	}
	delete(s.credentials, tables.CredentialKindLegacyPassword)
	credential.Kind = tables.CredentialKindPassword
	credential.SecretHash = newHash
	credential.Version++
	s.credentials[tables.CredentialKindPassword] = credential
	return nil
}

func (s *localAuthenticationStoreStub) ChangeLocalPasswordCredential(_ context.Context, userID, credentialID string, expectedVersion uint64, newHash string, _ time.Time) error {
	credential := s.credentials[tables.CredentialKindPassword]
	if credential == nil || credential.UserID != userID || credential.ID != credentialID || credential.Version != expectedVersion || !credential.IsActive {
		return errors.New("credential changed")
	}
	credential.SecretHash = newHash
	credential.Version++
	s.changed = true
	return nil
}

func TestLocalAuthenticationServiceUpgradesLegacyCredentialAndChangesPassword(t *testing.T) {
	now := time.Date(2026, time.September, 20, 9, 0, 0, 0, time.UTC)
	email := "User@example.test"
	legacyHash, err := bcrypt.GenerateFromPassword([]byte("old password"), bcrypt.MinCost)
	require.NoError(t, err)
	store := &localAuthenticationStoreStub{
		user: &tables.TableUser{ID: "user-1", Email: &email, NormalizedEmail: strPtr(tables.NormalizeEmail(email)), Status: tables.UserStatusActive, AuthVersion: 1},
		credentials: map[string]*tables.TableCredential{
			tables.CredentialKindLegacyPassword: {ID: "credential-1", UserID: "user-1", Kind: tables.CredentialKindLegacyPassword, SecretHash: string(legacyHash), Version: 1, IsActive: true},
		},
	}
	service := NewLocalAuthenticationService(store, NewPasswordService(), NewLoginThrottle(LoginThrottleConfig{}), func() time.Time { return now })

	user, err := service.Authenticate(context.Background(), "user@example.test", "old password", "127.0.0.1")
	require.NoError(t, err)
	require.NotNil(t, user)
	upgraded := store.credentials[tables.CredentialKindPassword]
	require.NotNil(t, upgraded)
	assert.Equal(t, tables.CredentialKindPassword, upgraded.Kind)
	assert.Contains(t, upgraded.SecretHash, "$argon2id$v=1$")

	require.NoError(t, service.ChangePassword(context.Background(), user.ID, "old password", "new password"))
	assert.True(t, store.changed)
	_, err = service.Authenticate(context.Background(), "user@example.test", "old password", "127.0.0.1")
	require.ErrorIs(t, err, ErrInvalidCredentials)
	_, err = service.Authenticate(context.Background(), "user@example.test", "new password", "127.0.0.1")
	require.NoError(t, err)
}

func TestLocalAuthenticationServiceRejectsUnknownAndDisabledAccounts(t *testing.T) {
	now := time.Date(2026, time.September, 20, 9, 0, 0, 0, time.UTC)
	service := NewLocalAuthenticationService(&localAuthenticationStoreStub{}, NewPasswordService(), NewLoginThrottle(LoginThrottleConfig{}), func() time.Time { return now })
	_, err := service.Authenticate(context.Background(), "unknown@example.test", "password", "127.0.0.1")
	require.ErrorIs(t, err, ErrInvalidCredentials)

	email := "disabled@example.test"
	service.store = &localAuthenticationStoreStub{user: &tables.TableUser{ID: "disabled", Email: &email, NormalizedEmail: strPtr(email), Status: tables.UserStatusDisabled}}
	_, err = service.Authenticate(context.Background(), email, "password", "127.0.0.1")
	require.ErrorIs(t, err, ErrInvalidCredentials)
}

func strPtr(value string) *string { return &value }
