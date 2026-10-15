package tables

import "time"

// TableOutboxEvent records a delivery that must survive process crashes after
// its corresponding administrative transaction commits. PayloadJSON is
// deliberately excluded from JSON responses; callers expose a domain-specific
// safe view instead.
type TableOutboxEvent struct {
	ID               string     `gorm:"primaryKey;type:varchar(255)" json:"id"`
	Topic            string     `gorm:"type:varchar(255);not null;index" json:"topic"`
	DeduplicationKey string     `gorm:"type:varchar(512);not null;uniqueIndex:idx_identity_outbox_deduplication" json:"deduplication_key"`
	PayloadJSON      string     `gorm:"type:text;not null;default:'{}'" json:"-"`
	AvailableAt      time.Time  `gorm:"not null;index:idx_identity_outbox_available" json:"available_at"`
	ClaimToken       *string    `gorm:"type:varchar(255);index" json:"-"`
	ClaimedUntil     *time.Time `gorm:"index:idx_identity_outbox_available" json:"-"`
	DeliveredAt      *time.Time `gorm:"index:idx_identity_outbox_available" json:"delivered_at,omitempty"`
	Attempts         int        `gorm:"not null;default:0" json:"attempts"`
	LastError        string     `gorm:"type:varchar(1024);not null;default:''" json:"last_error,omitempty"`
	CreatedAt        time.Time  `gorm:"not null;index" json:"created_at"`
	UpdatedAt        time.Time  `gorm:"not null" json:"updated_at"`

	Payload map[string]any `gorm:"-" json:"payload,omitempty"`
}

// TableName sets the stable database table name.
func (TableOutboxEvent) TableName() string { return "identity_outbox_events" }
