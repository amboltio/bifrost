package tables

import "time"

const (
	// RecoveryTokenPurposeEnrollment lets an administrator provision a
	// password without returning a reusable credential.
	RecoveryTokenPurposeEnrollment = "enrollment"
	// RecoveryTokenPurposeReset permits a one-time password reset.
	RecoveryTokenPurposeReset = "reset"
)

// TableRecoveryToken stores only a SHA-256 digest of an enrollment or reset
// credential. The plaintext is returned once by the authorized issuer and is
// never persisted, logged, or added to audit changed-fields.
type TableRecoveryToken struct {
	ID              string     `gorm:"primaryKey;type:varchar(255)" json:"id"`
	UserID          string     `gorm:"type:varchar(255);not null;index:idx_identity_recovery_user_purpose,priority:1" json:"user_id"`
	Purpose         string     `gorm:"type:varchar(64);not null;index:idx_identity_recovery_user_purpose,priority:2" json:"purpose"`
	TokenDigest     string     `gorm:"type:varchar(64);not null;uniqueIndex:idx_identity_recovery_digest" json:"-"`
	ExpiresAt       time.Time  `gorm:"not null;index" json:"expires_at"`
	ConsumedAt      *time.Time `gorm:"index" json:"consumed_at,omitempty"`
	CreatedByUserID *string    `gorm:"type:varchar(255);index" json:"created_by_user_id,omitempty"`
	CreatedAt       time.Time  `gorm:"not null;index" json:"created_at"`
	UpdatedAt       time.Time  `gorm:"not null" json:"updated_at"`
}

// TableName sets the stable table name.
func (TableRecoveryToken) TableName() string { return "identity_recovery_tokens" }
