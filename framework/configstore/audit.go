package configstore

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	maxAuditChangedFields = 64
	maxAuditCollection    = 64
	maxAuditStringBytes   = 1024
	maxOutboxErrorBytes   = 1024
)

// AuditEventsQueryParams defines the durable journal read contract. A nil
// VisibleTargetIDs means the internal caller is intentionally unrestricted;
// an empty non-nil slice means the caller has no visible targets and receives
// no rows. HTTP authorization will always install a non-nil scope.
type AuditEventsQueryParams struct {
	ActorPrincipal   *string
	TargetType       *string
	Action           *string
	RequestID        *string
	VisibleTargetIDs []string
	Before           *time.Time
	Limit            int
	Offset           int
}

// AuditStore owns append-only event persistence and scoped journal reads.
type AuditStore interface {
	CreateAuditEvent(ctx context.Context, event *tables.TableAuditEvent, tx ...*gorm.DB) error
	ListAuditEvents(ctx context.Context, params AuditEventsQueryParams) ([]tables.TableAuditEvent, int64, error)
	DeleteAuditEventsBefore(ctx context.Context, before time.Time) (int64, error)
}

// OutboxStore owns durable event delivery coordination. Claim tokens make an
// event delivery idempotent from the worker's perspective: only its holder can
// acknowledge or release the lease it obtained.
type OutboxStore interface {
	CreateOutboxEvent(ctx context.Context, event *tables.TableOutboxEvent, tx ...*gorm.DB) error
	ClaimOutboxEvents(ctx context.Context, now time.Time, lease time.Duration, limit int) ([]tables.TableOutboxEvent, string, error)
	MarkOutboxEventDelivered(ctx context.Context, id, claimToken string, deliveredAt time.Time) error
	ReleaseOutboxEvent(ctx context.Context, id, claimToken, deliveryError string, retryAt time.Time) error
}

// AuditedChangeStore performs an administrative mutation, its audit event,
// and the cache-invalidation outbox event in a single transaction.
type AuditedChangeStore interface {
	ApplyAuditedChange(ctx context.Context, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent, mutate func(*gorm.DB) error) error
}

// HMACLoginIdentifier returns a stable correlation value for failed logins
// without storing an email/username. Callers must supply deployment-secret
// material; an empty key is rejected rather than quietly becoming predictable.
func HMACLoginIdentifier(key []byte, identifier string) (string, error) {
	if len(key) == 0 {
		return "", fmt.Errorf("login identifier HMAC key cannot be empty")
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(tables.NormalizeEmail(identifier)))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// NewFailedLoginAuditEvent creates a bounded, correlation-safe failed-login
// record. It intentionally does not include the original identifier in any
// target or changed-fields value.
func NewFailedLoginAuditEvent(hmacKey []byte, identifier, requestID string, occurredAt time.Time) (*tables.TableAuditEvent, error) {
	identifierHMAC, err := HMACLoginIdentifier(hmacKey, identifier)
	if err != nil {
		return nil, err
	}
	var requestIDPtr *string
	if requestID = strings.TrimSpace(requestID); requestID != "" {
		requestIDPtr = &requestID
	}
	return &tables.TableAuditEvent{
		ActorPrincipal: "anonymous",
		TargetType:     "login",
		Action:         tables.AuditActionLoginFailed,
		RequestID:      requestIDPtr,
		IdentifierHMAC: &identifierHMAC,
		OccurredAt:     occurredAt.UTC(),
		ChangedFields:  map[string]any{"outcome": "rejected"},
	}, nil
}

// PrepareAuditEvent crosses the only allowed changed-fields serialization
// boundary. Rejecting caller-supplied raw JSON prevents a handler from
// accidentally bypassing recursive secret redaction.
func PrepareAuditEvent(event *tables.TableAuditEvent) error {
	if event == nil {
		return fmt.Errorf("audit event cannot be nil")
	}
	if strings.TrimSpace(event.ActorPrincipal) == "" || strings.TrimSpace(event.TargetType) == "" || strings.TrimSpace(event.Action) == "" {
		return fmt.Errorf("audit event actor principal, target type, and action are required")
	}
	if event.ID == "" {
		event.ID = uuid.NewString()
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = time.Now().UTC()
	} else {
		event.OccurredAt = event.OccurredAt.UTC()
	}
	if event.ChangedFields == nil && event.ChangedFieldsJSON != "" && event.ChangedFieldsJSON != "{}" {
		return fmt.Errorf("audit event changed fields must use ChangedFields, not raw JSON")
	}
	changedFields, err := json.Marshal(SanitizeAuditFields(event.ChangedFields))
	if err != nil {
		return fmt.Errorf("marshal redacted audit changed fields: %w", err)
	}
	event.ChangedFieldsJSON = string(changedFields)
	return nil
}

// PrepareOutboxEvent bounds the durable delivery payload and applies the same
// secret-key redaction as audit values. Cache-invalidation payloads should be
// small handles (IDs, versions, topics), never serialized credentials.
func PrepareOutboxEvent(event *tables.TableOutboxEvent) error {
	if event == nil {
		return fmt.Errorf("outbox event cannot be nil")
	}
	event.Topic = strings.TrimSpace(event.Topic)
	event.DeduplicationKey = strings.TrimSpace(event.DeduplicationKey)
	if event.Topic == "" || event.DeduplicationKey == "" {
		return fmt.Errorf("outbox event topic and deduplication key are required")
	}
	if event.ID == "" {
		event.ID = uuid.NewString()
	}
	if event.AvailableAt.IsZero() {
		event.AvailableAt = time.Now().UTC()
	} else {
		event.AvailableAt = event.AvailableAt.UTC()
	}
	if event.Payload == nil && event.PayloadJSON != "" && event.PayloadJSON != "{}" {
		return fmt.Errorf("outbox event payload must use Payload, not raw JSON")
	}
	payload, err := json.Marshal(SanitizeAuditFields(event.Payload))
	if err != nil {
		return fmt.Errorf("marshal outbox payload: %w", err)
	}
	event.PayloadJSON = string(payload)
	return nil
}

// SanitizeAuditFields creates a bounded copy suitable for audit or outbox
// storage. Sensitive key names are redacted recursively; strings and nested
// collections are capped so request headers or provider claims cannot become
// unbounded journal data.
func SanitizeAuditFields(fields map[string]any) map[string]any {
	return sanitizeAuditFields(fields, 0)
}

func sanitizeAuditFields(fields map[string]any, depth int) map[string]any {
	if len(fields) == 0 {
		return map[string]any{}
	}
	if depth >= 8 {
		return map[string]any{"_truncated": "[TRUNCATED]"}
	}
	result := make(map[string]any, min(len(fields), maxAuditChangedFields))
	count := 0
	for key, value := range fields {
		if count == maxAuditChangedFields {
			result["_truncated"] = true
			break
		}
		if isSensitiveAuditKey(key) {
			result[key] = "[REDACTED]"
		} else {
			result[key] = sanitizeAuditValue(value, depth+1)
		}
		count++
	}
	return result
}

func isSensitiveAuditKey(key string) bool {
	key = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "_", ""), "-", ""))
	for _, sensitive := range []string{"password", "secret", "token", "authorization", "cookie", "credential", "apikey", "privatekey"} {
		if strings.Contains(key, sensitive) {
			return true
		}
	}
	return false
}

func sanitizeAuditValue(value any, depth int) any {
	if depth >= 8 {
		return "[TRUNCATED]"
	}
	switch typed := value.(type) {
	case string:
		return truncateAuditString(typed)
	case []byte:
		return "[REDACTED]"
	case map[string]any:
		return sanitizeAuditFields(typed, depth)
	case map[string]string:
		converted := make(map[string]any, len(typed))
		for key, value := range typed {
			converted[key] = value
		}
		return sanitizeAuditFields(converted, depth)
	case []any:
		limit := min(len(typed), maxAuditCollection)
		result := make([]any, 0, limit)
		for _, item := range typed[:limit] {
			result = append(result, sanitizeAuditValue(item, depth+1))
		}
		if len(typed) > limit {
			result = append(result, "[TRUNCATED]")
		}
		return result
	default:
		return value
	}
}

func truncateAuditString(value string) string {
	if len(value) <= maxAuditStringBytes {
		return value
	}
	return value[:maxAuditStringBytes] + "[TRUNCATED]"
}

func decodeAuditEvent(event *tables.TableAuditEvent) error {
	if event.ChangedFieldsJSON == "" {
		event.ChangedFields = map[string]any{}
		return nil
	}
	if err := json.Unmarshal([]byte(event.ChangedFieldsJSON), &event.ChangedFields); err != nil {
		return fmt.Errorf("decode audit changed fields: %w", err)
	}
	return nil
}

func decodeOutboxEvent(event *tables.TableOutboxEvent) error {
	if event.PayloadJSON == "" {
		event.Payload = map[string]any{}
		return nil
	}
	if err := json.Unmarshal([]byte(event.PayloadJSON), &event.Payload); err != nil {
		return fmt.Errorf("decode outbox payload: %w", err)
	}
	return nil
}

// CreateAuditEvent appends one validated, redacted journal row.
func (s *RDBConfigStore) CreateAuditEvent(ctx context.Context, event *tables.TableAuditEvent, tx ...*gorm.DB) error {
	if err := PrepareAuditEvent(event); err != nil {
		return err
	}
	if err := s.identityDB(tx).WithContext(ctx).Create(event).Error; err != nil {
		return s.parseGormError(err)
	}
	return nil
}

// ListAuditEvents applies the caller's durable target scope before counting,
// paging, and reading. Permission resolution supplies that scope at the HTTP
// boundary in the authorization task.
func (s *RDBConfigStore) ListAuditEvents(ctx context.Context, params AuditEventsQueryParams) ([]tables.TableAuditEvent, int64, error) {
	query := s.ScopedDB(ctx).Model(&tables.TableAuditEvent{})
	if params.ActorPrincipal != nil {
		query = query.Where("actor_principal = ?", *params.ActorPrincipal)
	}
	if params.TargetType != nil {
		query = query.Where("target_type = ?", *params.TargetType)
	}
	if params.Action != nil {
		query = query.Where("action = ?", *params.Action)
	}
	if params.RequestID != nil {
		query = query.Where("request_id = ?", *params.RequestID)
	}
	if params.VisibleTargetIDs != nil {
		if len(params.VisibleTargetIDs) == 0 {
			return []tables.TableAuditEvent{}, 0, nil
		}
		query = query.Where("target_id IN ?", params.VisibleTargetIDs)
	}
	if params.Before != nil {
		query = query.Where("occurred_at < ?", params.Before.UTC())
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	limit := params.Limit
	if limit <= 0 {
		limit = 50
	} else if limit > 100 {
		limit = 100
	}
	offset := max(params.Offset, 0)
	var events []tables.TableAuditEvent
	if err := query.Order("occurred_at DESC, id DESC").Offset(offset).Limit(limit).Find(&events).Error; err != nil {
		return nil, 0, err
	}
	for index := range events {
		if err := decodeAuditEvent(&events[index]); err != nil {
			return nil, 0, err
		}
	}
	return events, total, nil
}

// DeleteAuditEventsBefore supports an explicit retention worker. It has no
// implicit timer so a deployment cannot lose evidence solely because a process
// happened to restart.
func (s *RDBConfigStore) DeleteAuditEventsBefore(ctx context.Context, before time.Time) (int64, error) {
	result := s.DB().WithContext(ctx).Where("occurred_at < ?", before.UTC()).Delete(&tables.TableAuditEvent{})
	return result.RowsAffected, result.Error
}

// CreateOutboxEvent adds a durable event that can be delivered after the
// caller's transaction commits.
func (s *RDBConfigStore) CreateOutboxEvent(ctx context.Context, event *tables.TableOutboxEvent, tx ...*gorm.DB) error {
	if err := PrepareOutboxEvent(event); err != nil {
		return err
	}
	if err := s.identityDB(tx).WithContext(ctx).Create(event).Error; err != nil {
		return s.parseGormError(err)
	}
	return nil
}

// ApplyAuditedChange keeps the state change, immutable audit row, and outbox
// row atomic. A commit failure rolls back every write; later delivery failures
// only affect the outbox retry state and never undo an authenticated change.
func (s *RDBConfigStore) ApplyAuditedChange(ctx context.Context, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent, mutate func(*gorm.DB) error) error {
	if mutate == nil {
		return fmt.Errorf("audited change mutation cannot be nil")
	}
	if err := PrepareAuditEvent(auditEvent); err != nil {
		return err
	}
	if err := PrepareOutboxEvent(outboxEvent); err != nil {
		return err
	}
	return s.DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := mutate(tx); err != nil {
			return err
		}
		if err := tx.Create(auditEvent).Error; err != nil {
			return s.parseGormError(err)
		}
		if err := tx.Create(outboxEvent).Error; err != nil {
			return s.parseGormError(err)
		}
		return nil
	})
}

// ClaimOutboxEvents leases pending events. PostgreSQL obtains SKIP LOCKED row
// locks; SQLite serializes writers. A lease expiry makes a crash-recovered event
// eligible for another worker without considering it delivered.
func (s *RDBConfigStore) ClaimOutboxEvents(ctx context.Context, now time.Time, lease time.Duration, limit int) ([]tables.TableOutboxEvent, string, error) {
	if lease <= 0 {
		lease = time.Minute
	}
	if limit <= 0 {
		limit = 25
	} else if limit > 100 {
		limit = 100
	}
	now = now.UTC()
	claimUntil := now.Add(lease)
	claimToken := uuid.NewString()
	var claimed []tables.TableOutboxEvent

	err := s.DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		query := tx.Where("delivered_at IS NULL AND available_at <= ? AND (claimed_until IS NULL OR claimed_until <= ?)", now, now).
			Order("available_at ASC, id ASC").Limit(limit)
		if tx.Dialector.Name() == "postgres" {
			query = query.Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"})
		}
		if err := query.Find(&claimed).Error; err != nil {
			return err
		}
		for index := range claimed {
			result := tx.Model(&tables.TableOutboxEvent{}).
				Where("id = ? AND delivered_at IS NULL AND (claimed_until IS NULL OR claimed_until <= ?)", claimed[index].ID, now).
				Updates(map[string]any{"claim_token": claimToken, "claimed_until": claimUntil})
			if result.Error != nil {
				return result.Error
			}
			if result.RowsAffected == 0 {
				return fmt.Errorf("outbox event %s was claimed concurrently", claimed[index].ID)
			}
			claimed[index].ClaimToken = &claimToken
			claimed[index].ClaimedUntil = &claimUntil
		}
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	for index := range claimed {
		if err := decodeOutboxEvent(&claimed[index]); err != nil {
			return nil, "", err
		}
	}
	return claimed, claimToken, nil
}

// MarkOutboxEventDelivered acknowledges exactly the worker claim token that
// leased the event. Duplicate acknowledgement attempts are safe and visible as
// ErrNotFound to the stale worker.
func (s *RDBConfigStore) MarkOutboxEventDelivered(ctx context.Context, id, claimToken string, deliveredAt time.Time) error {
	result := s.DB().WithContext(ctx).Model(&tables.TableOutboxEvent{}).
		Where("id = ? AND claim_token = ? AND delivered_at IS NULL", id, claimToken).
		Updates(map[string]any{"delivered_at": deliveredAt.UTC(), "claim_token": nil, "claimed_until": nil, "last_error": ""})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// ReleaseOutboxEvent records a bounded delivery failure and makes the same row
// eligible for a retry. It does not create a second event, so a worker restart
// keeps one durable delivery history.
func (s *RDBConfigStore) ReleaseOutboxEvent(ctx context.Context, id, claimToken, deliveryError string, retryAt time.Time) error {
	result := s.DB().WithContext(ctx).Model(&tables.TableOutboxEvent{}).
		Where("id = ? AND claim_token = ? AND delivered_at IS NULL", id, claimToken).
		Updates(map[string]any{
			"available_at": retryAt.UTC(), "claim_token": nil, "claimed_until": nil,
			"attempts": gorm.Expr("attempts + ?", 1), "last_error": truncateAuditString(deliveryError),
		})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// IsDuplicateOutboxDelivery reports the storage response that makes a stale
// worker safe to stop processing after another worker completed the event.
func IsDuplicateOutboxDelivery(err error) bool {
	return errors.Is(err, ErrNotFound)
}
