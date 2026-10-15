// Package audit coordinates durable outbox delivery for security and
// governance events. It deliberately has no HTTP dependency: authentication
// failures are recorded synchronously, while transport delivery is retried by
// this worker after commit.
package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/maximhq/bifrost/framework/configstore"
	"github.com/maximhq/bifrost/framework/configstore/tables"
)

// Delivery sends one durable event to the configured consumer. A returned
// error is persisted for retry; it never changes the already-committed action
// that produced the event.
type Delivery func(context.Context, tables.TableOutboxEvent) error

// Clock makes retry and lease behavior deterministic in tests.
type Clock func() time.Time

// Service claims, sends, and settles outbox events. It has no unbounded in
// memory queue: durable state remains authoritative across worker restarts.
type Service struct {
	store      configstore.OutboxStore
	delivery   Delivery
	now        Clock
	lease      time.Duration
	retryDelay time.Duration
}

// NewService constructs a worker with bounded claims and a one-minute lease.
func NewService(store configstore.OutboxStore, delivery Delivery, now Clock) (*Service, error) {
	if store == nil {
		return nil, fmt.Errorf("outbox store cannot be nil")
	}
	if delivery == nil {
		return nil, fmt.Errorf("outbox delivery cannot be nil")
	}
	if now == nil {
		now = time.Now
	}
	return &Service{store: store, delivery: delivery, now: now, lease: time.Minute, retryDelay: time.Minute}, nil
}

// DeliverPending processes at most limit events. Delivery errors are persisted
// as retries and do not escape to a request handler, which keeps failed login
// and authorization responses independent of an audit consumer outage.
func (s *Service) DeliverPending(ctx context.Context, limit int) (int, error) {
	now := s.now().UTC()
	events, claimToken, err := s.store.ClaimOutboxEvents(ctx, now, s.lease, limit)
	if err != nil {
		return 0, err
	}
	for _, event := range events {
		if err := s.delivery(ctx, event); err != nil {
			if releaseErr := s.store.ReleaseOutboxEvent(ctx, event.ID, claimToken, err.Error(), now.Add(s.retryDelay)); releaseErr != nil && !configstore.IsDuplicateOutboxDelivery(releaseErr) {
				return 0, releaseErr
			}
			continue
		}
		if err := s.store.MarkOutboxEventDelivered(ctx, event.ID, claimToken, s.now().UTC()); err != nil && !configstore.IsDuplicateOutboxDelivery(err) {
			return 0, err
		}
	}
	return len(events), nil
}
