package tables

import "time"

const (
	ProjectAccessRuleUnion     = "union"
	ProjectAccessRuleIntersect = "intersect"
	ProjectMembershipExplicit  = "explicit"
	ProjectMembershipOpen      = "open"
	ProjectAccountingBoth      = "both"
	ProjectAccountingProject   = "project_only"
	ProjectAccountingPrincipal = "principal_only"
	ProjectSplitNone           = "none"
	ProjectSplitEqual          = "equal"
)

// TableProject stores the durable request-scoped governance boundary. Policy
// lists are metadata-only in OSS and are resolved by the governance plugin.
type TableProject struct {
	ID                string     `gorm:"primaryKey;type:varchar(255)" json:"id"`
	Name              string     `gorm:"type:varchar(255);not null;uniqueIndex" json:"name"`
	Description       string     `gorm:"type:text;not null;default:''" json:"description"`
	Enabled           bool       `gorm:"not null;default:true" json:"enabled"`
	ExpiresAt         *time.Time `gorm:"index" json:"expires_at,omitempty"`
	AccessRule        string     `gorm:"type:varchar(32);not null;default:'union'" json:"access_rule"`
	MembershipMode    string     `gorm:"type:varchar(32);not null;default:'explicit'" json:"membership_mode"`
	AccountingMode    string     `gorm:"type:varchar(32);not null;default:'both'" json:"accounting_mode"`
	SplitPolicy       string     `gorm:"type:varchar(32);not null;default:'none'" json:"split_policy"`
	AllowAllProviders bool       `gorm:"not null;default:false" json:"allow_all_providers"`
	AllowedProviders  []string   `gorm:"serializer:json;type:text;not null;default:'[]'" json:"allowed_providers"`
	AllowedModels     []string   `gorm:"serializer:json;type:text;not null;default:'[]'" json:"allowed_models"`
	CreatedByUserID   *string    `gorm:"type:varchar(255);index" json:"created_by_user_id,omitempty"`
	CreatedAt         time.Time  `gorm:"index;not null" json:"created_at"`
	UpdatedAt         time.Time  `gorm:"index;not null" json:"updated_at"`
}

func (TableProject) TableName() string { return "governance_projects" }

type TableProjectMember struct {
	ID               string    `gorm:"primaryKey;type:varchar(255)" json:"id"`
	ProjectID        string    `gorm:"type:varchar(255);not null;index;uniqueIndex:idx_identity_project_member_source,priority:1" json:"project_id"`
	UserID           string    `gorm:"type:varchar(255);not null;index;uniqueIndex:idx_identity_project_member_source,priority:2" json:"user_id"`
	Source           string    `gorm:"type:varchar(64);not null;default:'manual';uniqueIndex:idx_identity_project_member_source,priority:3" json:"source"`
	ProviderID       *string   `gorm:"type:varchar(255);index" json:"provider_id,omitempty"`
	AssignedByUserID *string   `gorm:"type:varchar(255);index" json:"assigned_by_user_id,omitempty"`
	CreatedAt        time.Time `gorm:"index;not null" json:"created_at"`
	UpdatedAt        time.Time `gorm:"index;not null" json:"updated_at"`
}

func (TableProjectMember) TableName() string { return "identity_project_members" }
