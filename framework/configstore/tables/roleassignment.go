package tables

import "time"

// TableRoleAssignment grants a catalog role to a canonical user. Database
// uniqueness makes assignment creation idempotent across replica retries.
type TableRoleAssignment struct {
	ID               string    `gorm:"primaryKey;type:varchar(255)" json:"id"`
	UserID           string    `gorm:"type:varchar(255);not null;index;uniqueIndex:idx_identity_role_assignments_user_role,priority:1" json:"user_id"`
	RoleID           string    `gorm:"type:varchar(255);not null;index;uniqueIndex:idx_identity_role_assignments_user_role,priority:2" json:"role_id"`
	AssignedByUserID *string   `gorm:"type:varchar(255);index" json:"assigned_by_user_id,omitempty"`
	CreatedAt        time.Time `gorm:"index;not null" json:"created_at"`
	UpdatedAt        time.Time `gorm:"index;not null" json:"updated_at"`
}

// TableName sets the stable database table name.
func (TableRoleAssignment) TableName() string { return "identity_role_assignments" }
