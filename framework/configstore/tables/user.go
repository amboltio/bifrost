package tables

import (
	"strings"
	"time"

	"gorm.io/gorm"
)

const (
	// UserStatusActive allows a user to authenticate and receive grants.
	UserStatusActive = "active"
	// UserStatusDisabled preserves the durable identity while blocking every
	// credential that resolves to it.
	UserStatusDisabled = "disabled"
)

// NormalizeEmail produces the stable lookup value for a user email. It keeps
// provider-specific local-part semantics intact: Bifrost only trims surrounding
// whitespace and performs case-insensitive matching.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// TableUser is the canonical identity for a person in a deployment. Passwords
// and external-provider credentials live in their own tables so a profile
// response can never accidentally include credential material.
type TableUser struct {
	ID              string     `gorm:"primaryKey;type:varchar(255)" json:"id"`
	Email           *string    `gorm:"type:varchar(320)" json:"email,omitempty"`
	NormalizedEmail *string    `gorm:"type:varchar(320);uniqueIndex:idx_identity_users_normalized_email" json:"normalized_email,omitempty"`
	LegacyUsername  *string    `gorm:"type:varchar(255);uniqueIndex:idx_identity_users_legacy_username" json:"legacy_username,omitempty"`
	DisplayName     string     `gorm:"type:varchar(255);not null;default:''" json:"display_name"`
	Status          string     `gorm:"type:varchar(32);not null;default:'active';index" json:"status"`
	AuthVersion     uint64     `gorm:"not null;default:1" json:"auth_version"`
	CreatedByUserID *string    `gorm:"type:varchar(255);index" json:"created_by_user_id,omitempty"`
	DisabledAt      *time.Time `gorm:"index" json:"disabled_at,omitempty"`
	CreatedAt       time.Time  `gorm:"index;not null" json:"created_at"`
	UpdatedAt       time.Time  `gorm:"index;not null" json:"updated_at"`
}

// TableName sets the stable database table name.
func (TableUser) TableName() string { return "identity_users" }

// BeforeSave normalizes only lookup fields. Display email preserves the
// administrator-selected spelling, and an imported legacy user may omit email
// entirely until it completes the transitional email flow.
func (u *TableUser) BeforeSave(*gorm.DB) error {
	if u.Email != nil {
		email := strings.TrimSpace(*u.Email)
		if email == "" {
			u.Email = nil
			u.NormalizedEmail = nil
		} else {
			u.Email = &email
			normalized := NormalizeEmail(email)
			u.NormalizedEmail = &normalized
		}
	} else if u.NormalizedEmail != nil {
		normalized := NormalizeEmail(*u.NormalizedEmail)
		if normalized == "" {
			u.NormalizedEmail = nil
		} else {
			u.NormalizedEmail = &normalized
		}
	}

	if u.LegacyUsername != nil {
		username := strings.TrimSpace(*u.LegacyUsername)
		if username == "" {
			u.LegacyUsername = nil
		} else {
			u.LegacyUsername = &username
		}
	}
	if u.Status == "" {
		u.Status = UserStatusActive
	}
	if u.AuthVersion == 0 {
		u.AuthVersion = 1
	}
	return nil
}
