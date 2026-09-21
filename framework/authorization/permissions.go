// Package authorization contains the typed management permissions and role
// evaluation used at the authenticated HTTP boundary.
package authorization

import "slices"

// Permission identifies one management action. The catalog is deliberately
// small for the first user-administration slice and grows with each protected
// vertical slice; an absent route manifest entry is denied by the transport.
type Permission string

const (
	PermissionUsersRead           Permission = "users.read"
	PermissionUsersCreate         Permission = "users.create"
	PermissionUsersUpdate         Permission = "users.update"
	PermissionUsersResetPassword  Permission = "users.reset_password"
	PermissionUsersRevokeSessions Permission = "users.revoke_sessions"
	PermissionUsersAssignRoles    Permission = "users.assign_roles"
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
	}
}
