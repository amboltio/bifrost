package tables

import "time"

const (
	UserVirtualKeySourceManual        = "manual"
	UserVirtualKeySourceOIDCClaim     = "oidc_claim"
	UserVirtualKeySourceDirectorySync = "directory_sync"
)

// TableUserVirtualKeyAssignment records ownership without duplicating the
// secret stored on the virtual-key row. Revoked assignments remain queryable
// for audit and never grant access at runtime.
type TableUserVirtualKeyAssignment struct {
	ID               string     `gorm:"primaryKey;type:varchar(255)" json:"id"`
	UserID           string     `gorm:"type:varchar(255);not null;index;uniqueIndex:idx_identity_user_virtual_key_source,priority:1" json:"user_id"`
	VirtualKeyID     string     `gorm:"type:varchar(255);not null;index;uniqueIndex:idx_identity_user_virtual_key_source,priority:2" json:"virtual_key_id"`
	Source           string     `gorm:"type:varchar(64);not null;default:'manual';uniqueIndex:idx_identity_user_virtual_key_source,priority:3" json:"source"`
	AssignedByUserID *string    `gorm:"type:varchar(255);index" json:"assigned_by_user_id,omitempty"`
	RevokedAt        *time.Time `gorm:"index" json:"revoked_at,omitempty"`
	CreatedAt        time.Time  `gorm:"index;not null" json:"created_at"`
	UpdatedAt        time.Time  `gorm:"index;not null" json:"updated_at"`
}

func (TableUserVirtualKeyAssignment) TableName() string {
	return "identity_user_virtual_key_assignments"
}
