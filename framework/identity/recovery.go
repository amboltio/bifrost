package identity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/maximhq/bifrost/framework/configstore"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/maximhq/bifrost/framework/encrypt"
)

// DefaultRecoveryTokenTTL bounds an enrollment/reset link when an operator
// does not choose a shorter lifetime.
const DefaultRecoveryTokenTTL = 30 * time.Minute

// RecoveryService issues plaintext credentials exactly once and delegates the
// digest-only persistence and transactional redemption to configstore.
type RecoveryService struct {
	store     configstore.RecoveryTokenStore
	passwords *PasswordService
	now       func() time.Time
	ttl       time.Duration
}

// NewRecoveryService constructs the service with the deployment password
// policy. Nil dependencies return actionable errors from operations instead of
// silently accepting a reset that cannot be persisted.
func NewRecoveryService(store configstore.RecoveryTokenStore, passwords *PasswordService, now func() time.Time) *RecoveryService {
	if now == nil {
		now = time.Now
	}
	return &RecoveryService{store: store, passwords: passwords, now: now, ttl: DefaultRecoveryTokenTTL}
}

// Issue returns the raw recovery token exactly once. The store receives only
// its digest, so audit events and database backups cannot replay the URL.
func (s *RecoveryService) Issue(ctx context.Context, userID, purpose string, createdByUserID *string) (string, time.Time, error) {
	return s.issue(ctx, userID, purpose, createdByUserID, func(token *tables.TableRecoveryToken) error {
		return s.store.CreateRecoveryToken(ctx, token)
	})
}

// IssueAudited issues a raw recovery token once while atomically persisting
// its digest, the administrator audit event, and an invalidation outbox event.
// It refuses to downgrade to unaudited persistence when the store lacks the
// audited contract.
func (s *RecoveryService) IssueAudited(ctx context.Context, userID, purpose string, createdByUserID *string, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) (string, time.Time, error) {
	auditedStore, ok := s.store.(configstore.AuditedRecoveryTokenStore)
	if !ok {
		return "", time.Time{}, fmt.Errorf("audited recovery token store is required")
	}
	return s.issue(ctx, userID, purpose, createdByUserID, func(token *tables.TableRecoveryToken) error {
		return auditedStore.CreateRecoveryTokenAudited(ctx, token, auditEvent, outboxEvent)
	})
}

func (s *RecoveryService) issue(ctx context.Context, userID, purpose string, createdByUserID *string, persist func(*tables.TableRecoveryToken) error) (string, time.Time, error) {
	if s.store == nil {
		return "", time.Time{}, fmt.Errorf("recovery token store is required")
	}
	if persist == nil {
		return "", time.Time{}, fmt.Errorf("recovery token persistence is required")
	}
	if strings.TrimSpace(userID) == "" || !validRecoveryPurpose(purpose) {
		return "", time.Time{}, fmt.Errorf("recovery token user ID and purpose are required")
	}
	rawBytes := make([]byte, 32)
	if _, err := rand.Read(rawBytes); err != nil {
		return "", time.Time{}, fmt.Errorf("generate recovery token: %w", err)
	}
	raw := base64.RawURLEncoding.EncodeToString(rawBytes)
	now := s.now().UTC()
	expiresAt := now.Add(s.ttl)
	if err := persist(&tables.TableRecoveryToken{
		UserID: userID, Purpose: purpose, TokenDigest: encrypt.HashSHA256(raw),
		ExpiresAt: expiresAt, CreatedByUserID: createdByUserID,
	}); err != nil {
		return "", time.Time{}, err
	}
	return raw, expiresAt, nil
}

// Redeem verifies the new password before consuming a recovery token. The
// store atomically burns the token, replaces the credential, increments the
// user auth version, and revokes every active session.
func (s *RecoveryService) Redeem(ctx context.Context, rawToken, newPassword string) (*tables.TableRecoveryToken, error) {
	if s.store == nil || s.passwords == nil {
		return nil, fmt.Errorf("recovery service is not configured")
	}
	if strings.TrimSpace(rawToken) == "" {
		return nil, configstore.ErrNotFound
	}
	hash, err := s.passwords.Hash(newPassword)
	if err != nil {
		return nil, err
	}
	return s.store.RedeemRecoveryToken(ctx, encrypt.HashSHA256(rawToken), hash, s.now().UTC())
}

func validRecoveryPurpose(value string) bool {
	return value == tables.RecoveryTokenPurposeEnrollment || value == tables.RecoveryTokenPurposeReset
}
