package authorization

import "github.com/maximhq/bifrost/framework/configstore/tables"

const (
	RoleIDUserManager = "user_manager"
	RoleIDViewer      = "viewer"
)

// SeededRoles returns fresh system-role records. The migration inserts missing
// rows but never replaces a manually edited permission set on an existing
// non-super-admin role.
func SeededRoles() []tables.TableRole {
	return []tables.TableRole{
		{
			ID: tables.RoleIDSuperAdmin, Name: tables.RoleNameSuperAdmin, DisplayName: "Super administrator",
			Permissions: permissionStrings(Catalog()), IsSystem: true, IsImmutable: true,
		},
		{
			ID: RoleIDUserManager, Name: RoleIDUserManager, DisplayName: "User manager",
			Permissions: permissionStrings([]Permission{
				PermissionUsersRead, PermissionUsersCreate, PermissionUsersUpdate,
				PermissionUsersResetPassword, PermissionUsersRevokeSessions, PermissionUsersAssignRoles,
				PermissionUserAnalyticsRead,
				PermissionAccessProfilesRead, PermissionAccessProfilesCreate, PermissionAccessProfilesUpdate,
				PermissionAccessProfilesDelete, PermissionAccessProfilesAssign,
			}),
			IsSystem: true,
		},
		{
			ID: RoleIDViewer, Name: RoleIDViewer, DisplayName: "Viewer",
			Permissions: []string{string(PermissionUsersRead), string(PermissionUserAnalyticsRead)}, IsSystem: true,
		},
	}
}

func permissionStrings(permissions []Permission) []string {
	result := make([]string, len(permissions))
	for index, permission := range permissions {
		result[index] = string(permission)
	}
	return result
}
