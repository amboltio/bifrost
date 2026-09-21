package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/maximhq/bifrost/framework/configstore/tables"
)

// ErrInvalidCredentials is intentionally generic. HTTP callers must use the
// same response for an unknown user, inactive account, malformed verifier, or
// incorrect password.
var ErrInvalidCredentials = errors.New("invalid credentials")

// LocalAuthenticationStore is the narrow storage boundary for local password
// authentication. Both password updates predicate on the credential version,
// so a concurrent reset or password change cannot be silently overwritten.
type LocalAuthenticationStore interface {
	GetUserByNormalizedEmail(ctx context.Context, email string) (*tables.TableUser, error)
	GetUserByLegacyUsername(ctx context.Context, username string) (*tables.TableUser, error)
	GetCredentialByUserIDAndKind(ctx context.Context, userID, kind string) (*tables.TableCredential, error)
	UpgradeLocalPasswordCredential(ctx context.Context, userID, credentialID string, expectedVersion uint64, newHash string) error
	ChangeLocalPasswordCredential(ctx context.Context, userID, credentialID string, expectedVersion uint64, newHash string, changedAt time.Time) error
}

// LocalAuthenticationService verifies local credentials without exposing a
// password verifier outside the identity boundary.
type LocalAuthenticationService struct {
	store     LocalAuthenticationStore
	passwords *PasswordService
	throttle  *LoginThrottle
	now       func() time.Time
}

func NewLocalAuthenticationService(store LocalAuthenticationStore, passwords *PasswordService, throttle *LoginThrottle, now func() time.Time) *LocalAuthenticationService {
	if passwords == nil {
		passwords = NewPasswordService()
	}
	if throttle == nil {
		throttle = NewLoginThrottle(LoginThrottleConfig{})
	}
	if now == nil {
		now = time.Now
	}
	return &LocalAuthenticationService{store: store, passwords: passwords, throttle: throttle, now: now}
}

// Authenticate finds a canonical account by normalized email or its one-time
// legacy username, verifies an active password verifier, and persists a
// successful bcrypt upgrade before reporting success.
func (s *LocalAuthenticationService) Authenticate(ctx context.Context, identifier, password, clientIP string) (*tables.TableUser, error) {
	if s.store == nil || strings.TrimSpace(identifier) == "" || !s.throttle.Allow(identifier, clientIP, s.now().UTC()) {
		return nil, ErrInvalidCredentials
	}
	user, err := s.store.GetUserByNormalizedEmail(ctx, identifier)
	if err != nil {
		return nil, err
	}
	if user == nil {
		user, err = s.store.GetUserByLegacyUsername(ctx, identifier)
		if err != nil {
			return nil, err
		}
	}
	if user == nil || user.Status != tables.UserStatusActive {
		s.passwords.DummyVerify(password)
		return nil, ErrInvalidCredentials
	}
	credential, err := s.activeLocalCredential(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	if credential == nil {
		s.passwords.DummyVerify(password)
		return nil, ErrInvalidCredentials
	}
	verified, upgrade, err := s.passwords.VerifyAndUpgrade(credential.SecretHash, password)
	if err != nil || !verified {
		return nil, ErrInvalidCredentials
	}
	if upgrade != "" {
		if err := s.store.UpgradeLocalPasswordCredential(ctx, user.ID, credential.ID, credential.Version, upgrade); err != nil {
			return nil, err
		}
	}
	return user, nil
}

// ChangePassword verifies the current password and revokes every existing
// session atomically with the new verifier. The caller must have already
// authenticated the user session and supplied that user ID.
func (s *LocalAuthenticationService) ChangePassword(ctx context.Context, userID, currentPassword, newPassword string) error {
	if s.store == nil || strings.TrimSpace(userID) == "" {
		return ErrInvalidCredentials
	}
	credential, err := s.activeLocalCredential(ctx, userID)
	if err != nil || credential == nil {
		return ErrInvalidCredentials
	}
	verified, _, err := s.passwords.VerifyAndUpgrade(credential.SecretHash, currentPassword)
	if err != nil || !verified {
		return ErrInvalidCredentials
	}
	newHash, err := s.passwords.Hash(newPassword)
	if err != nil {
		return fmt.Errorf("hash new password: %w", err)
	}
	if err := s.store.ChangeLocalPasswordCredential(ctx, userID, credential.ID, credential.Version, newHash, s.now().UTC()); err != nil {
		return err
	}
	return nil
}

func (s *LocalAuthenticationService) activeLocalCredential(ctx context.Context, userID string) (*tables.TableCredential, error) {
	password, err := s.store.GetCredentialByUserIDAndKind(ctx, userID, tables.CredentialKindPassword)
	if err != nil {
		return nil, err
	}
	if password != nil && password.IsActive {
		return password, nil
	}
	legacy, err := s.store.GetCredentialByUserIDAndKind(ctx, userID, tables.CredentialKindLegacyPassword)
	if err != nil {
		return nil, err
	}
	if legacy != nil && legacy.IsActive {
		return legacy, nil
	}
	return nil, nil
}
