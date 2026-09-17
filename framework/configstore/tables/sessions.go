package tables

import (
	"fmt"
	"time"

	"github.com/maximhq/bifrost/framework/encrypt"
	"gorm.io/gorm"
)

// SessionsTable represents a session in the database
type SessionsTable struct {
	ID                int        `gorm:"primaryKey;autoIncrement" json:"id"`
	Token             string     `gorm:"type:text;not null;uniqueIndex" json:"token"`
	ExpiresAt         time.Time  `gorm:"index;not null" json:"expires_at,omitempty"`
	UserID            *string    `gorm:"type:varchar(255);index" json:"user_id,omitempty"`
	AuthMethod        string     `gorm:"type:varchar(64);not null;default:'legacy';index" json:"auth_method"`
	ProviderID        *string    `gorm:"type:varchar(255);index" json:"provider_id,omitempty"`
	LastSeenAt        *time.Time `gorm:"index" json:"last_seen_at,omitempty"`
	AbsoluteExpiresAt *time.Time `gorm:"index" json:"absolute_expires_at,omitempty"`
	IdleExpiresAt     *time.Time `gorm:"index" json:"idle_expires_at,omitempty"`
	RevokedAt         *time.Time `gorm:"index" json:"revoked_at,omitempty"`
	AuthVersion       uint64     `gorm:"not null;default:0" json:"auth_version"`
	CreatedAt         time.Time  `gorm:"index;not null" json:"created_at"`
	UpdatedAt         time.Time  `gorm:"index;not null" json:"updated_at"`
	EncryptionStatus  string     `gorm:"type:varchar(20);default:'plain_text'" json:"-"`
	TokenHash         string     `gorm:"type:varchar(64);index:idx_session_token_hash,unique" json:"-"`
}

// TableName sets the table name for each model
func (SessionsTable) TableName() string { return "sessions" }

// BeforeSave hook to hash and encrypt the session token
func (s *SessionsTable) BeforeSave(tx *gorm.DB) error {
	if s.AuthMethod == "" {
		s.AuthMethod = "legacy"
	}
	// Hash must be computed before encryption (from plaintext value)
	if s.Token != "" {
		s.TokenHash = encrypt.HashSHA256(s.Token)
	}
	if encrypt.IsEnabled() && s.Token != "" {
		if err := encryptString(&s.Token); err != nil {
			return fmt.Errorf("failed to encrypt session token: %w", err)
		}
		s.EncryptionStatus = EncryptionStatusEncrypted
	}
	return nil
}

// IsActiveAt centralizes the transitional session-expiry bridge. ExpiresAt
// remains authoritative for pre-identity rows; identity-issued sessions also
// carry absolute and idle deadlines, both of which must remain valid.
func (s SessionsTable) IsActiveAt(now time.Time) bool {
	now = now.UTC()
	if s.RevokedAt != nil && !s.RevokedAt.After(now) {
		return false
	}
	if s.ExpiresAt.IsZero() || !s.ExpiresAt.After(now) {
		return false
	}
	if s.AbsoluteExpiresAt != nil && !s.AbsoluteExpiresAt.After(now) {
		return false
	}
	if s.IdleExpiresAt != nil && !s.IdleExpiresAt.After(now) {
		return false
	}
	return true
}

// AfterFind hook to decrypt the session token
func (s *SessionsTable) AfterFind(tx *gorm.DB) error {
	if s.EncryptionStatus == EncryptionStatusEncrypted {
		if err := decryptString(&s.Token); err != nil {
			return fmt.Errorf("failed to decrypt session token: %w", err)
		}
	}
	return nil
}
