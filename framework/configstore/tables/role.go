package tables

import "time"

const (
	// RoleIDSuperAdmin is stable so bootstrap can lock and assign the immutable
	// bypass role without a name lookup race.
	RoleIDSuperAdmin   = "super_admin"
	RoleNameSuperAdmin = "super_admin"
)

// TableRole is the minimal role catalog needed while identity bootstrap ships.
// The detailed permission payload arrives with the authorization vertical
// slice; this row is intentionally not a policy store.
type TableRole struct {
	ID          string    `gorm:"primaryKey;type:varchar(255)" json:"id"`
	Name        string    `gorm:"type:varchar(255);not null;uniqueIndex:idx_identity_roles_name" json:"name"`
	DisplayName string    `gorm:"type:varchar(255);not null;default:''" json:"display_name"`
	IsSystem    bool      `gorm:"not null;default:false" json:"is_system"`
	IsImmutable bool      `gorm:"not null;default:false" json:"is_immutable"`
	CreatedAt   time.Time `gorm:"index;not null" json:"created_at"`
	UpdatedAt   time.Time `gorm:"index;not null" json:"updated_at"`
}

// TableName sets the stable database table name.
func (TableRole) TableName() string { return "identity_roles" }
