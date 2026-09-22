package tables

import "time"

const (
	BusinessUnitSourceManual        = "manual"
	BusinessUnitSourceOIDCClaim     = "oidc_claim"
	BusinessUnitSourceDirectorySync = "directory_sync"
)

// TableBusinessUnit is the durable organization node between customers and
// teams. It intentionally keeps hierarchy references optional so deployments
// can introduce business units without rewriting existing team data.
type TableBusinessUnit struct {
	ID              string         `gorm:"primaryKey;type:varchar(255)" json:"id"`
	Name            string         `gorm:"type:varchar(255);not null;uniqueIndex" json:"name"`
	Description     string         `gorm:"type:text;not null;default:''" json:"description"`
	CustomerID      *string        `gorm:"type:varchar(255);index" json:"customer_id,omitempty"`
	CreatedByUserID *string        `gorm:"type:varchar(255);index" json:"created_by_user_id,omitempty"`
	CreatedAt       time.Time      `gorm:"index;not null" json:"created_at"`
	UpdatedAt       time.Time      `gorm:"index;not null" json:"updated_at"`
	Customer        *TableCustomer `gorm:"foreignKey:CustomerID" json:"customer,omitempty"`
}

func (TableBusinessUnit) TableName() string { return "governance_business_units" }

// TableUserBusinessUnitMembership keeps IdP assignment provenance so a sync
// can remove only memberships it owns.
type TableUserBusinessUnitMembership struct {
	ID               string    `gorm:"primaryKey;type:varchar(255)" json:"id"`
	UserID           string    `gorm:"type:varchar(255);not null;index;uniqueIndex:idx_identity_user_business_unit_source,priority:1" json:"user_id"`
	BusinessUnitID   string    `gorm:"type:varchar(255);not null;index;uniqueIndex:idx_identity_user_business_unit_source,priority:2" json:"business_unit_id"`
	Source           string    `gorm:"type:varchar(64);not null;default:'manual';uniqueIndex:idx_identity_user_business_unit_source,priority:3" json:"source"`
	ProviderID       *string   `gorm:"type:varchar(255);index" json:"provider_id,omitempty"`
	AssignedByUserID *string   `gorm:"type:varchar(255);index" json:"assigned_by_user_id,omitempty"`
	CreatedAt        time.Time `gorm:"index;not null" json:"created_at"`
	UpdatedAt        time.Time `gorm:"index;not null" json:"updated_at"`
}

func (TableUserBusinessUnitMembership) TableName() string {
	return "identity_user_business_unit_memberships"
}

// TableTeamBusinessUnitMembership models the recommended Customer → business
// unit → team hierarchy while retaining source ownership for reconciliation.
type TableTeamBusinessUnitMembership struct {
	ID               string    `gorm:"primaryKey;type:varchar(255)" json:"id"`
	TeamID           string    `gorm:"type:varchar(255);not null;index;uniqueIndex:idx_identity_team_business_unit_source,priority:1" json:"team_id"`
	BusinessUnitID   string    `gorm:"type:varchar(255);not null;index;uniqueIndex:idx_identity_team_business_unit_source,priority:2" json:"business_unit_id"`
	Source           string    `gorm:"type:varchar(64);not null;default:'manual';uniqueIndex:idx_identity_team_business_unit_source,priority:3" json:"source"`
	ProviderID       *string   `gorm:"type:varchar(255);index" json:"provider_id,omitempty"`
	AssignedByUserID *string   `gorm:"type:varchar(255);index" json:"assigned_by_user_id,omitempty"`
	CreatedAt        time.Time `gorm:"index;not null" json:"created_at"`
	UpdatedAt        time.Time `gorm:"index;not null" json:"updated_at"`
}

func (TableTeamBusinessUnitMembership) TableName() string {
	return "identity_team_business_unit_memberships"
}
