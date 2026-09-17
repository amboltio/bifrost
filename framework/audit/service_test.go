package audit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

type memoryOutboxStore struct {
	event      tables.TableOutboxEvent
	claimed    bool
	delivered  bool
	released   int
	claimToken string
}

func (s *memoryOutboxStore) CreateOutboxEvent(context.Context, *tables.TableOutboxEvent, ...*gorm.DB) error {
	return errors.New("not used by dispatcher")
}

func (s *memoryOutboxStore) ClaimOutboxEvents(_ context.Context, _ time.Time, _ time.Duration, _ int) ([]tables.TableOutboxEvent, string, error) {
	if s.delivered || s.claimed {
		return nil, "", nil
	}
	s.claimed = true
	s.claimToken = "claim-1"
	return []tables.TableOutboxEvent{s.event}, s.claimToken, nil
}

func (s *memoryOutboxStore) MarkOutboxEventDelivered(_ context.Context, id, token string, _ time.Time) error {
	if !s.claimed || id != s.event.ID || token != s.claimToken {
		return errors.New("stale claim")
	}
	s.delivered = true
	s.claimed = false
	return nil
}

func (s *memoryOutboxStore) ReleaseOutboxEvent(_ context.Context, id, token, _ string, _ time.Time) error {
	if !s.claimed || id != s.event.ID || token != s.claimToken {
		return errors.New("stale claim")
	}
	s.released++
	s.claimed = false
	return nil
}

func TestServiceRetriesDurableEventAfterWorkerRestart(t *testing.T) {
	now := time.Date(2026, 9, 17, 10, 0, 0, 0, time.UTC)
	store := &memoryOutboxStore{event: tables.TableOutboxEvent{ID: "event-1", Topic: "identity.invalidate"}}
	first, err := NewService(store, func(context.Context, tables.TableOutboxEvent) error {
		return errors.New("consumer unavailable")
	}, func() time.Time { return now })
	require.NoError(t, err)
	processed, err := first.DeliverPending(context.Background(), 10)
	require.NoError(t, err)
	assert.Equal(t, 1, processed)
	assert.Equal(t, 1, store.released)
	assert.False(t, store.delivered)

	second, err := NewService(store, func(context.Context, tables.TableOutboxEvent) error { return nil }, func() time.Time { return now.Add(time.Minute) })
	require.NoError(t, err)
	processed, err = second.DeliverPending(context.Background(), 10)
	require.NoError(t, err)
	assert.Equal(t, 1, processed)
	assert.True(t, store.delivered)
}
