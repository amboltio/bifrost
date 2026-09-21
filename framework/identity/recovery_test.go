package identity

import (
	"context"
	"testing"
	"time"

	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

type recoveryStoreStub struct {
	created  *tables.TableRecoveryToken
	redeemed string
	newHash  string
	audited  bool
}

func (s *recoveryStoreStub) CreateRecoveryToken(_ context.Context, token *tables.TableRecoveryToken, _ ...*gorm.DB) error {
	copy := *token
	s.created = &copy
	return nil
}

func (s *recoveryStoreStub) CreateRecoveryTokenAudited(ctx context.Context, token *tables.TableRecoveryToken, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) error {
	if auditEvent == nil || outboxEvent == nil || auditEvent.Action == "" || outboxEvent.DeduplicationKey == "" {
		return assert.AnError
	}
	s.audited = true
	return s.CreateRecoveryToken(ctx, token)
}

func (s *recoveryStoreStub) RedeemRecoveryToken(_ context.Context, digest, passwordHash string, _ time.Time) (*tables.TableRecoveryToken, error) {
	s.redeemed, s.newHash = digest, passwordHash
	return &tables.TableRecoveryToken{ID: "recovery-1", UserID: "user-1"}, nil
}

func TestRecoveryServiceReturnsPlaintextOnceAndPersistsDigest(t *testing.T) {
	store := &recoveryStoreStub{}
	now := time.Date(2026, time.September, 17, 15, 0, 0, 0, time.UTC)
	service := NewRecoveryService(store, NewPasswordService(), func() time.Time { return now })
	raw, expiresAt, err := service.Issue(context.Background(), "user-1", tables.RecoveryTokenPurposeReset, nil)
	require.NoError(t, err)
	assert.NotEmpty(t, raw)
	assert.Equal(t, now.Add(DefaultRecoveryTokenTTL), expiresAt)
	require.NotNil(t, store.created)
	assert.NotEqual(t, raw, store.created.TokenDigest)
	assert.Len(t, store.created.TokenDigest, 64)

	redeemed, err := service.Redeem(context.Background(), raw, "new password")
	require.NoError(t, err)
	assert.Equal(t, "user-1", redeemed.UserID)
	assert.Equal(t, store.created.TokenDigest, store.redeemed)
	assert.NotEqual(t, "new password", store.newHash)
}

func TestRecoveryServiceIssuesAuditedTokenWithoutPersistingPlaintext(t *testing.T) {
	store := &recoveryStoreStub{}
	service := NewRecoveryService(store, NewPasswordService(), nil)
	userID := "user-1"
	raw, _, err := service.IssueAudited(context.Background(), userID, tables.RecoveryTokenPurposeReset, nil,
		&tables.TableAuditEvent{ActorPrincipal: "user:admin", TargetType: "user", TargetID: &userID, Action: "identity.user.password_reset_issued"},
		&tables.TableOutboxEvent{Topic: "identity.user.changed", DeduplicationKey: "recovery-1"},
	)
	require.NoError(t, err)
	assert.True(t, store.audited)
	require.NotNil(t, store.created)
	assert.NotEqual(t, raw, store.created.TokenDigest)
}
