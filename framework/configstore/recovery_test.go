package configstore

import (
	"context"
	"testing"
	"time"

	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/maximhq/bifrost/framework/encrypt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecoveryTokenMigrationCreatesDigestOnlyTable(t *testing.T) {
	store := setupLegacyBootstrapStore(t)
	require.NoError(t, migrationAddRecoveryTokens(context.Background(), store.DB(), testMigrationLogger))
	assert.True(t, store.DB().Migrator().HasTable(&tables.TableRecoveryToken{}))
}

func TestRDBRecoveryTokenRedeemsOnlyOnceAndRevokesSessions(t *testing.T) {
	store := setupLegacyBootstrapStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.September, 17, 14, 0, 0, 0, time.UTC)
	require.NoError(t, store.DB().AutoMigrate(&tables.TableRecoveryToken{}))
	user := &tables.TableUser{Email: ptr("recover@example.test")}
	require.NoError(t, store.CreateUser(ctx, user))
	require.NoError(t, store.CreateCredential(ctx, &tables.TableCredential{
		UserID: user.ID, Kind: tables.CredentialKindLegacyPassword, SecretHash: "$2a$legacy", IsActive: true,
	}))
	require.NoError(t, store.CreateSession(ctx, &tables.SessionsTable{
		Token: "recover-session", ExpiresAt: now.Add(time.Hour), UserID: &user.ID, AuthVersion: user.AuthVersion,
		CreatedAt: now, UpdatedAt: now,
	}))
	rawToken := "only-returned-on-issue"
	token := &tables.TableRecoveryToken{
		UserID: user.ID, Purpose: tables.RecoveryTokenPurposeReset,
		TokenDigest: encrypt.HashSHA256(rawToken), ExpiresAt: now.Add(time.Hour),
	}
	require.NoError(t, store.CreateRecoveryToken(ctx, token))

	redeemed, err := store.RedeemRecoveryToken(ctx, token.TokenDigest, "argon2id$new-hash", now)
	require.NoError(t, err)
	require.NotNil(t, redeemed.ConsumedAt)
	assert.Equal(t, user.ID, redeemed.UserID)

	credential, err := store.GetCredentialByUserIDAndKind(ctx, user.ID, tables.CredentialKindPassword)
	require.NoError(t, err)
	require.NotNil(t, credential)
	assert.Equal(t, "argon2id$new-hash", credential.SecretHash)
	legacy, err := store.GetCredentialByUserIDAndKind(ctx, user.ID, tables.CredentialKindLegacyPassword)
	require.NoError(t, err)
	assert.False(t, legacy.IsActive)

	updatedUser, err := store.GetUser(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, uint64(2), updatedUser.AuthVersion)
	session, err := store.GetSession(ctx, "recover-session")
	require.NoError(t, err)
	require.NotNil(t, session.RevokedAt)

	_, err = store.RedeemRecoveryToken(ctx, token.TokenDigest, "should-not-apply", now.Add(time.Minute))
	require.ErrorIs(t, err, ErrNotFound)
}
