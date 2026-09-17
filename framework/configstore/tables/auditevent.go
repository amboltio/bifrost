package tables

import "time"

const (
	// AuditActionLoginFailed is recorded without a raw login identifier. See
	// configstore.NewFailedLoginAuditEvent for the HMAC-only construction path.
	AuditActionLoginFailed = "auth.login_failed"
)

// TableAuditEvent is an append-only security journal row. ChangedFieldsJSON is
// populated only through the config-store redaction boundary; raw credentials,
// token values, and request headers never belong in this table.
type TableAuditEvent struct {
	ID                string    `gorm:"primaryKey;type:varchar(255)" json:"id"`
	ActorPrincipal    string    `gorm:"type:varchar(255);not null;index:idx_identity_audit_actor_time,priority:1" json:"actor_principal"`
	TargetType        string    `gorm:"type:varchar(128);not null;index:idx_identity_audit_target_time,priority:1" json:"target_type"`
	TargetID          *string   `gorm:"type:varchar(255);index:idx_identity_audit_target_time,priority:2" json:"target_id,omitempty"`
	Action            string    `gorm:"type:varchar(255);not null;index:idx_identity_audit_action_time,priority:1" json:"action"`
	RequestID         *string   `gorm:"type:varchar(255);index" json:"request_id,omitempty"`
	IdentifierHMAC    *string   `gorm:"type:varchar(64);index" json:"-"`
	ChangedFieldsJSON string    `gorm:"type:text;not null;default:'{}'" json:"-"`
	OccurredAt        time.Time `gorm:"not null;index:idx_identity_audit_actor_time,priority:2;index:idx_identity_audit_target_time,priority:3;index:idx_identity_audit_action_time,priority:2" json:"occurred_at"`
	CreatedAt         time.Time `gorm:"not null;index" json:"created_at"`

	// ChangedFields is decoded only after values have crossed the durable
	// redaction boundary. It has no database column.
	ChangedFields map[string]any `gorm:"-" json:"changed_fields,omitempty"`
}

// TableName sets the stable database table name.
func (TableAuditEvent) TableName() string { return "identity_audit_events" }
