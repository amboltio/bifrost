package configstore

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupAuditTestStore(t *testing.T) *RDBConfigStore {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&tables.TableUser{}, &tables.TableAuditEvent{}, &tables.TableOutboxEvent{}))
	store := &RDBConfigStore{}
	store.db.Store(db)
	return store
}

func TestAuditMigrationCreatesJournalAndOutboxTables(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	require.NoError(t, triggerMigrations(context.Background(), db, testMigrationLogger))

	for _, table := range []string{"identity_audit_events", "identity_outbox_events"} {
		var count int64
		require.NoError(t, db.Raw("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?", table).Scan(&count).Error)
		require.Equalf(t, int64(1), count, "expected durable audit table %q", table)
	}
}

func TestRDBAuditStoreRedactsSecretsAndFailedLoginIdentifiers(t *testing.T) {
	store := setupAuditTestStore(t)
	ctx := context.Background()
	userID := "user-1"
	now := time.Date(2026, time.September, 17, 9, 0, 0, 0, time.UTC)
	event := &tables.TableAuditEvent{
		ActorPrincipal: "user:admin", TargetType: "user", TargetID: &userID,
		Action: "user.updated", OccurredAt: now,
		ChangedFields: map[string]any{
			"display_name": "Alice",
			"password":     "should-never-persist",
			"nested": map[string]any{
				"authorization": "Bearer should-never-persist",
			},
		},
	}
	require.NoError(t, store.CreateAuditEvent(ctx, event))
	assert.NotContains(t, event.ChangedFieldsJSON, "should-never-persist")
	assert.Contains(t, event.ChangedFieldsJSON, "[REDACTED]")

	failed, err := NewFailedLoginAuditEvent([]byte("audit-hmac-key"), " Alice@example.test ", "request-1", now)
	require.NoError(t, err)
	require.NoError(t, store.CreateAuditEvent(ctx, failed))
	require.NotNil(t, failed.IdentifierHMAC)
	assert.NotEqual(t, "alice@example.test", *failed.IdentifierHMAC)

	var rows []tables.TableAuditEvent
	require.NoError(t, store.DB().Order("occurred_at ASC, id ASC").Find(&rows).Error)
	require.Len(t, rows, 2)
	raw, err := json.Marshal(rows)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "should-never-persist")
	assert.NotContains(t, string(raw), "Alice@example.test")
	assert.NotContains(t, string(raw), "alice@example.test")

	nested := map[string]any{"leaf": "value"}
	for range 10 {
		nested = map[string]any{"nested": nested}
	}
	deepJSON, err := json.Marshal(SanitizeAuditFields(nested))
	require.NoError(t, err)
	assert.Contains(t, string(deepJSON), "[TRUNCATED]")

	visible, total, err := store.ListAuditEvents(ctx, AuditEventsQueryParams{VisibleTargetIDs: []string{userID}})
	require.NoError(t, err)
	require.Equal(t, int64(1), total)
	require.Len(t, visible, 1)
	assert.Equal(t, "[REDACTED]", visible[0].ChangedFields["password"])
}

func TestRDBAuditStoreAppliesMutationJournalAndOutboxAtomically(t *testing.T) {
	store := setupAuditTestStore(t)
	ctx := context.Background()
	firstOutbox := &tables.TableOutboxEvent{Topic: "identity.invalidate", DeduplicationKey: "duplicate", Payload: map[string]any{"user_id": "other"}}
	require.NoError(t, store.CreateOutboxEvent(ctx, firstOutbox))

	userID := "rollback-user"
	err := store.ApplyAuditedChange(ctx,
		&tables.TableAuditEvent{ActorPrincipal: "user:admin", TargetType: "user", TargetID: &userID, Action: "user.disabled"},
		&tables.TableOutboxEvent{Topic: "identity.invalidate", DeduplicationKey: "duplicate", Payload: map[string]any{"user_id": userID}},
		func(tx *gorm.DB) error {
			return tx.Create(&tables.TableUser{ID: userID, Email: ptr("rollback@example.test")}).Error
		},
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAlreadyExists)

	var users, audits, outbox int64
	require.NoError(t, store.DB().Model(&tables.TableUser{}).Count(&users).Error)
	require.NoError(t, store.DB().Model(&tables.TableAuditEvent{}).Count(&audits).Error)
	require.NoError(t, store.DB().Model(&tables.TableOutboxEvent{}).Count(&outbox).Error)
	assert.Zero(t, users)
	assert.Zero(t, audits)
	assert.Equal(t, int64(1), outbox)

	require.NoError(t, store.ApplyAuditedChange(ctx,
		&tables.TableAuditEvent{ActorPrincipal: "user:admin", TargetType: "user", TargetID: &userID, Action: "user.disabled"},
		&tables.TableOutboxEvent{Topic: "identity.invalidate", DeduplicationKey: "rollback-user:v2", Payload: map[string]any{"user_id": userID}},
		func(tx *gorm.DB) error {
			return tx.Create(&tables.TableUser{ID: userID, Email: ptr("committed@example.test")}).Error
		},
	))
	require.NoError(t, store.DB().Model(&tables.TableUser{}).Count(&users).Error)
	require.NoError(t, store.DB().Model(&tables.TableAuditEvent{}).Count(&audits).Error)
	require.NoError(t, store.DB().Model(&tables.TableOutboxEvent{}).Count(&outbox).Error)
	assert.Equal(t, int64(1), users)
	assert.Equal(t, int64(1), audits)
	assert.Equal(t, int64(2), outbox)
}

func TestRDBAuditStoreScopesBeforePaginationAndRecoversOutboxLease(t *testing.T) {
	store := setupAuditTestStore(t)
	ctx := context.Background()
	one, two := "user-1", "user-2"
	for _, event := range []*tables.TableAuditEvent{
		{ActorPrincipal: "user:admin", TargetType: "user", TargetID: &one, Action: "user.updated", OccurredAt: time.Date(2026, 9, 17, 9, 0, 0, 0, time.UTC)},
		{ActorPrincipal: "user:admin", TargetType: "user", TargetID: &two, Action: "user.updated", OccurredAt: time.Date(2026, 9, 17, 9, 1, 0, 0, time.UTC)},
		{ActorPrincipal: "user:admin", TargetType: "user", TargetID: &one, Action: "user.disabled", OccurredAt: time.Date(2026, 9, 17, 9, 2, 0, 0, time.UTC)},
	} {
		require.NoError(t, store.CreateAuditEvent(ctx, event))
	}

	visible, total, err := store.ListAuditEvents(ctx, AuditEventsQueryParams{VisibleTargetIDs: []string{one}, Limit: 1})
	require.NoError(t, err)
	assert.Equal(t, int64(2), total)
	require.Len(t, visible, 1)
	assert.Equal(t, one, *visible[0].TargetID)
	visible, total, err = store.ListAuditEvents(ctx, AuditEventsQueryParams{VisibleTargetIDs: []string{}})
	require.NoError(t, err)
	assert.Zero(t, total)
	assert.Empty(t, visible)

	event := &tables.TableOutboxEvent{Topic: "identity.invalidate", DeduplicationKey: "user-1:v1", Payload: map[string]any{"user_id": one, "token": "never-store"}}
	require.NoError(t, store.CreateOutboxEvent(ctx, event))
	assert.NotContains(t, event.PayloadJSON, "never-store")

	now := time.Date(2026, 9, 17, 10, 0, 0, 0, time.UTC)
	claimed, token, err := store.ClaimOutboxEvents(ctx, now, time.Minute, 5)
	require.NoError(t, err)
	require.Len(t, claimed, 1)
	assert.Equal(t, "[REDACTED]", claimed[0].Payload["token"])
	require.NoError(t, store.ReleaseOutboxEvent(ctx, event.ID, token, "consumer temporarily unavailable", now.Add(time.Second)))

	claimed, token, err = store.ClaimOutboxEvents(ctx, now.Add(2*time.Second), time.Minute, 5)
	require.NoError(t, err)
	require.Len(t, claimed, 1)
	require.NoError(t, store.MarkOutboxEventDelivered(ctx, event.ID, token, now.Add(3*time.Second)))
	_, _, err = store.ClaimOutboxEvents(ctx, now.Add(4*time.Second), time.Minute, 5)
	require.NoError(t, err)
	assert.True(t, errors.Is(store.MarkOutboxEventDelivered(ctx, event.ID, token, now), ErrNotFound))
}
