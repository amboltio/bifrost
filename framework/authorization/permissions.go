// Package authorization contains the typed management permissions and role
// evaluation used at the authenticated HTTP boundary.
package authorization

import "slices"

// Permission identifies one management action. The catalog is deliberately
// small for the first user-administration slice and grows with each protected
// vertical slice; an absent route manifest entry is denied by the transport.
type Permission string

const (
	PermissionUsersRead            Permission = "users.read"
	PermissionUsersCreate          Permission = "users.create"
	PermissionUsersUpdate          Permission = "users.update"
	PermissionUsersResetPassword   Permission = "users.reset_password"
	PermissionUsersRevokeSessions  Permission = "users.revoke_sessions"
	PermissionUsersAssignRoles     Permission = "users.assign_roles"
	PermissionAccessProfilesRead   Permission = "access_profiles.read"
	PermissionAccessProfilesCreate Permission = "access_profiles.create"
	PermissionAccessProfilesUpdate Permission = "access_profiles.update"
	PermissionAccessProfilesDelete Permission = "access_profiles.delete"
	PermissionAccessProfilesAssign Permission = "access_profiles.assign"
	PermissionProjectsRead         Permission = "projects.read"
	PermissionProjectsCreate       Permission = "projects.create"
	PermissionProjectsUpdate       Permission = "projects.update"
	PermissionProjectsDelete       Permission = "projects.delete"
	PermissionProjectsAssign       Permission = "projects.assign"
	PermissionVirtualKeysAssign    Permission = "virtual_keys.assign"
	PermissionUserAnalyticsRead    Permission = "user_analytics.read"
)

// Has reports whether a persisted role permission list grants permission.
func Has(permissions []string, permission Permission) bool {
	return slices.Contains(permissions, string(permission))
}

// Catalog is the stable, server-published list of permissions implemented by
// this build. It is copied so callers cannot mutate shared policy data.
func Catalog() []Permission {
	return []Permission{
		PermissionUsersRead,
		PermissionUsersCreate,
		PermissionUsersUpdate,
		PermissionUsersResetPassword,
		PermissionUsersRevokeSessions,
		PermissionUsersAssignRoles,
		PermissionAccessProfilesRead,
		PermissionAccessProfilesCreate,
		PermissionAccessProfilesUpdate,
		PermissionAccessProfilesDelete,
		PermissionAccessProfilesAssign,
		PermissionProjectsRead,
		PermissionProjectsCreate,
		PermissionProjectsUpdate,
		PermissionProjectsDelete,
		PermissionProjectsAssign,
		PermissionVirtualKeysAssign,
		PermissionUserAnalyticsRead,
	}
}
