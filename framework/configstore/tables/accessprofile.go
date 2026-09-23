package tables

import "time"

// AccessProfileSource identifies who owns a profile assignment. Keeping this
// provenance lets a directory reconciler replace only its own grants while
// preserving administrator-managed assignments.
const (
	AccessProfileSourceManual        = "manual"
	AccessProfileSourceOIDCClaim     = "oidc_claim"
	AccessProfileSourceDirectorySync = "directory_sync"
	RoleAccessProfileSourceManual    = "manual"
)

// TableAccessProfile stores a reusable, bounded governance policy. The
// allow-lists are intentionally JSON arrays so SQLite and PostgreSQL share the
// same representation while the policy remains easy to inspect and audit.
type TableAccessProfile struct {
	ID                string    `gorm:"primaryKey;type:varchar(255)" json:"id"`
	Name              string    `gorm:"type:varchar(255);not null;uniqueIndex" json:"name"`
	Description       string    `gorm:"type:text;not null;default:''" json:"description"`
	Enabled           bool      `gorm:"not null;default:true" json:"enabled"`
	AllowAllProviders bool      `gorm:"not null;default:false" json:"allow_all_providers"`
	AllowedProviders  []string  `gorm:"serializer:json;type:text;not null;default:'[]'" json:"allowed_providers"`
	AllowedModels     []string  `gorm:"serializer:json;type:text;not null;default:'[]'" json:"allowed_models"`
	AllowedMCPTools   []string  `gorm:"serializer:json;type:text;not null;default:'[]'" json:"allowed_mcp_tools"`
	CreatedByUserID   *string   `gorm:"type:varchar(255);index" json:"created_by_user_id,omitempty"`
	CreatedAt         time.Time `gorm:"index;not null" json:"created_at"`
	UpdatedAt         time.Time `gorm:"index;not null" json:"updated_at"`
}

func (TableAccessProfile) TableName() string { return "governance_access_profiles" }

// TableUserAccessProfileAssignment is the user-to-profile relation with
// source ownership and a stable audit trail.
type TableUserAccessProfileAssignment struct {
	ID               string    `gorm:"primaryKey;type:varchar(255)" json:"id"`
	UserID           string    `gorm:"type:varchar(255);not null;index;uniqueIndex:idx_identity_user_access_profile_source,priority:1" json:"user_id"`
	AccessProfileID  string    `gorm:"type:varchar(255);not null;index;uniqueIndex:idx_identity_user_access_profile_source,priority:2" json:"access_profile_id"`
	Source           string    `gorm:"type:varchar(64);not null;default:'manual';uniqueIndex:idx_identity_user_access_profile_source,priority:3" json:"source"`
	ProviderID       *string   `gorm:"type:varchar(255);index" json:"provider_id,omitempty"`
	AssignedByUserID *string   `gorm:"type:varchar(255);index" json:"assigned_by_user_id,omitempty"`
	CreatedAt        time.Time `gorm:"index;not null" json:"created_at"`
	UpdatedAt        time.Time `gorm:"index;not null" json:"updated_at"`
}

func (TableUserAccessProfileAssignment) TableName() string {
	return "identity_user_access_profile_assignments"
}

// TableRoleAccessProfileAssignment gives every member of a role the reusable
// access profile by default. Direct user assignments can add more profiles;
// duplicate profile identities are collapsed by the governance resolver.
type TableRoleAccessProfileAssignment struct {
	ID               string    `gorm:"primaryKey;type:varchar(255)" json:"id"`
	RoleID           string    `gorm:"type:varchar(255);not null;index;uniqueIndex:idx_identity_role_access_profile_source,priority:1" json:"role_id"`
	AccessProfileID  string    `gorm:"type:varchar(255);not null;index;uniqueIndex:idx_identity_role_access_profile_source,priority:2" json:"access_profile_id"`
	Source           string    `gorm:"type:varchar(64);not null;default:'manual';uniqueIndex:idx_identity_role_access_profile_source,priority:3" json:"source"`
	AssignedByUserID *string   `gorm:"type:varchar(255);index" json:"assigned_by_user_id,omitempty"`
	CreatedAt        time.Time `gorm:"index;not null" json:"created_at"`
	UpdatedAt        time.Time `gorm:"index;not null" json:"updated_at"`
}

func (TableRoleAccessProfileAssignment) TableName() string {
	return "identity_role_access_profile_assignments"
}
