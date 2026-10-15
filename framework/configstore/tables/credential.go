package tables

import "time"

const (
	// CredentialKindPassword contains a versioned password verifier, never a
	// plaintext password. The hashing format is introduced by the password
	// service in the following task.
	CredentialKindPassword = "password"
	// CredentialKindLegacyPassword holds an imported bcrypt verifier until the
	// user completes a successful password upgrade.
	CredentialKindLegacyPassword = "legacy_password"
)

// TableCredential stores a single user-bound verifier. SecretHash is excluded
// from JSON so handler DTOs must choose to expose a safe credential summary.
type TableCredential struct {
	ID         string    `gorm:"primaryKey;type:varchar(255)" json:"id"`
	UserID     string    `gorm:"type:varchar(255);not null;index;uniqueIndex:idx_identity_credentials_user_kind,priority:1" json:"user_id"`
	Kind       string    `gorm:"type:varchar(64);not null;uniqueIndex:idx_identity_credentials_user_kind,priority:2" json:"kind"`
	SecretHash string    `gorm:"type:text;not null" json:"-"`
	Version    uint64    `gorm:"not null;default:1" json:"version"`
	IsActive   bool      `gorm:"not null;default:true;index" json:"is_active"`
	CreatedAt  time.Time `gorm:"index;not null" json:"created_at"`
	UpdatedAt  time.Time `gorm:"index;not null" json:"updated_at"`
}

// TableName sets the stable database table name.
func (TableCredential) TableName() string { return "identity_credentials" }
