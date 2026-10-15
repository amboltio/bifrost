package configstore

import (
	"context"
	"time"

	"github.com/maximhq/bifrost/framework/configstore/tables"
	"gorm.io/gorm"
)

// UserStore is the deliberately narrow canonical-user contract. The role
// methods exist here only because bootstrap must assign super_admin before the
// full RBAC catalog is introduced.
type UserStore interface {
	CreateUser(ctx context.Context, user *tables.TableUser, tx ...*gorm.DB) error
	GetUser(ctx context.Context, id string) (*tables.TableUser, error)
	GetUserByNormalizedEmail(ctx context.Context, email string) (*tables.TableUser, error)
	UpdateUser(ctx context.Context, user *tables.TableUser, tx ...*gorm.DB) error
	DisableUser(ctx context.Context, id string, disabledAt time.Time) error
	CreateInitialSuperAdmin(ctx context.Context, user *tables.TableUser, credential *tables.TableCredential) (*tables.TableUser, error)
	GetRole(ctx context.Context, id string) (*tables.TableRole, error)
	AssignRole(ctx context.Context, assignment *tables.TableRoleAssignment, tx ...*gorm.DB) error
	GetUserRoleAssignments(ctx context.Context, userID string) ([]tables.TableRoleAssignment, error)
}

// CredentialStore owns password and future recovery verifier persistence.
type CredentialStore interface {
	CreateCredential(ctx context.Context, credential *tables.TableCredential, tx ...*gorm.DB) error
	GetCredentialByUserIDAndKind(ctx context.Context, userID, kind string) (*tables.TableCredential, error)
	ListCredentialsByUserID(ctx context.Context, userID string) ([]tables.TableCredential, error)
}

// ExternalIdentityStore binds an independently verified external subject to a
// user without placing raw claims in the database.
type ExternalIdentityStore interface {
	CreateExternalIdentity(ctx context.Context, identity *tables.TableExternalIdentity, tx ...*gorm.DB) error
	GetExternalIdentityByIssuerSubject(ctx context.Context, issuer, subject string) (*tables.TableExternalIdentity, error)
	TouchExternalIdentity(ctx context.Context, id string, seenAt time.Time) error
	SetExternalIdentityActive(ctx context.Context, id string, isActive bool) error
}

// UserProfile is the handler-facing identity DTO. Credentials intentionally do
// not appear in this type; callers must never reuse a persistence row as an
// API response.
type UserProfile struct {
	ID              string     `json:"id"`
	Email           *string    `json:"email,omitempty"`
	DisplayName     string     `json:"display_name"`
	Status          string     `json:"status"`
	AuthVersion     uint64     `json:"auth_version"`
	CreatedByUserID *string    `json:"created_by_user_id,omitempty"`
	DisabledAt      *time.Time `json:"disabled_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// NewUserProfile copies only values safe for an identity-management response.
func NewUserProfile(user tables.TableUser) UserProfile {
	return UserProfile{
		ID: user.ID, Email: user.Email, DisplayName: user.DisplayName,
		Status: user.Status, AuthVersion: user.AuthVersion,
		CreatedByUserID: user.CreatedByUserID, DisabledAt: user.DisabledAt,
		CreatedAt: user.CreatedAt, UpdatedAt: user.UpdatedAt,
	}
}
