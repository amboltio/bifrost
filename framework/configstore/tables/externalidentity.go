package tables

import (
	"strings"
	"time"

	"gorm.io/gorm"
)

// TableExternalIdentity binds a validated OIDC issuer and subject to one
// canonical user. It deliberately stores neither provider token material nor
// unbounded ID-token/UserInfo claims.
type TableExternalIdentity struct {
	ID         string     `gorm:"primaryKey;type:varchar(255)" json:"id"`
	UserID     string     `gorm:"type:varchar(255);not null;index" json:"user_id"`
	ProviderID string     `gorm:"type:varchar(255);not null;index" json:"provider_id"`
	Issuer     string     `gorm:"type:text;not null;uniqueIndex:idx_identity_external_issuer_subject,priority:1" json:"issuer"`
	Subject    string     `gorm:"type:varchar(1024);not null;uniqueIndex:idx_identity_external_issuer_subject,priority:2" json:"subject"`
	IsActive   bool       `gorm:"not null;default:true;index" json:"is_active"`
	LastSeenAt *time.Time `gorm:"index" json:"last_seen_at,omitempty"`
	CreatedAt  time.Time  `gorm:"index;not null" json:"created_at"`
	UpdatedAt  time.Time  `gorm:"index;not null" json:"updated_at"`
}

// TableName sets the stable database table name.
func (TableExternalIdentity) TableName() string { return "identity_external_identities" }

// BeforeSave removes accidental surrounding whitespace without altering the
// issuer/subject values verified by the OIDC layer.
func (i *TableExternalIdentity) BeforeSave(*gorm.DB) error {
	i.ProviderID = strings.TrimSpace(i.ProviderID)
	i.Issuer = strings.TrimSpace(i.Issuer)
	i.Subject = strings.TrimSpace(i.Subject)
	return nil
}
