package tables

import "time"

const (
	UserTeamSourceManual        = "manual"
	UserTeamSourceOIDCClaim     = "oidc_claim"
	UserTeamSourceDirectorySync = "directory_sync"
)

// TableUserTeamMembership records a user's team assignment and who owns that
// assignment. Source ownership lets directory reconciliation remove only the
// grants it created while preserving manual administrator choices.
type TableUserTeamMembership struct {
	ID               string     `gorm:"primaryKey;type:varchar(255)" json:"id"`
	UserID           string     `gorm:"type:varchar(255);not null;index;uniqueIndex:idx_identity_user_team_source,priority:1" json:"user_id"`
	TeamID           string     `gorm:"type:varchar(255);not null;index;uniqueIndex:idx_identity_user_team_source,priority:2" json:"team_id"`
	Source           string     `gorm:"type:varchar(64);not null;default:'manual';uniqueIndex:idx_identity_user_team_source,priority:3" json:"source"`
	ProviderID       *string    `gorm:"type:varchar(255);index" json:"provider_id,omitempty"`
	AssignedByUserID *string    `gorm:"type:varchar(255);index" json:"assigned_by_user_id,omitempty"`
	CreatedAt        time.Time  `gorm:"index;not null" json:"created_at"`
	UpdatedAt        time.Time  `gorm:"index;not null" json:"updated_at"`
	Team             *TableTeam `gorm:"foreignKey:TeamID" json:"team,omitempty"`
}

// TableName sets the stable table name for user/team memberships.
func (TableUserTeamMembership) TableName() string { return "identity_user_team_memberships" }
