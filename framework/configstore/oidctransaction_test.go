package configstore

import (
	"context"
	"testing"
	"time"

	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOIDCTransactionStoreClaimsStateOnlyOnceBeforeExpiry(t *testing.T) {
	store := setupIdentityTestStore(t, ":memory:")
	require.NoError(t, store.DB().AutoMigrate(&tables.TableOIDCTransaction{}))

	now := time.Date(2026, time.September, 21, 12, 0, 0, 0, time.UTC)
	txn := &tables.TableOIDCTransaction{
		StateHash:    "state-hash",
		NonceHash:    "nonce-hash",
		ProviderID:   "example",
		CodeVerifier: "pkce-verifier",
		RedirectPath: "/governance/users",
		ExpiresAt:    now.Add(10 * time.Minute),
	}
	require.NoError(t, store.CreateOIDCTransaction(context.Background(), txn))

	claimed, err := store.ClaimOIDCTransaction(context.Background(), txn.StateHash, now)
	require.NoError(t, err)
	require.NotNil(t, claimed)
	assert.Equal(t, txn.ID, claimed.ID)
	assert.Equal(t, "pkce-verifier", claimed.CodeVerifier)
	assert.NotNil(t, claimed.ConsumedAt)

	replay, err := store.ClaimOIDCTransaction(context.Background(), txn.StateHash, now)
	require.NoError(t, err)
	assert.Nil(t, replay)
}

func TestOIDCTransactionStoreRejectsExpiredStateAndDeletesExpiredRows(t *testing.T) {
	store := setupIdentityTestStore(t, ":memory:")
	require.NoError(t, store.DB().AutoMigrate(&tables.TableOIDCTransaction{}))

	now := time.Date(2026, time.September, 21, 12, 0, 0, 0, time.UTC)
	expired := &tables.TableOIDCTransaction{
		StateHash: "expired-state", NonceHash: "nonce", ProviderID: "example",
		CodeVerifier: "pkce-verifier", RedirectPath: "/", ExpiresAt: now.Add(-time.Minute),
	}
	require.NoError(t, store.CreateOIDCTransaction(context.Background(), expired))

	claimed, err := store.ClaimOIDCTransaction(context.Background(), expired.StateHash, now)
	require.NoError(t, err)
	assert.Nil(t, claimed)

	deleted, err := store.DeleteExpiredOIDCTransactions(context.Background(), now)
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted)
}
