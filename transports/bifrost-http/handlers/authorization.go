package handlers

import (
	"context"
	"strings"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/authorization"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/valyala/fasthttp"
)

// UserRoleResolver is the narrow authorization read contract. Authentication
// remains responsible for proving a session; this middleware only evaluates
// the already-stamped canonical principal against durable role grants.
type UserRoleResolver interface {
	GetRolesByUserID(ctx context.Context, userID string) ([]tables.TableRole, error)
}

// NewIdentityAuthorizationMiddleware applies fail-closed route policy to
// canonical dashboard sessions. Legacy authenticated administration and an
// explicitly disabled authentication configuration remain compatible through
// their trusted middleware markers. Every canonical management path without a
// manifest entry is denied until its feature slice defines a permission.
func NewIdentityAuthorizationMiddleware(resolver UserRoleResolver) schemas.BifrostHTTPMiddleware {
	return func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
		return func(ctx *fasthttp.RequestCtx) {
			if authBypassed(ctx) || isTrustedLocalAdmin(ctx) {
				next(ctx)
				return
			}

			userID, _ := ctx.UserValue(schemas.BifrostContextKeyUserID).(string)
			userID = strings.TrimSpace(userID)
			if userID == "" {
				// Authentication middleware already decided whether a non-canonical
				// compatibility credential is valid. RBAC applies only after a
				// canonical principal is present.
				next(ctx)
				return
			}

			method := string(ctx.Method())
			path := string(ctx.Path())
			if isCanonicalSelfServiceRoute(method, path) {
				next(ctx)
				return
			}

			if resolver == nil {
				SendError(ctx, fasthttp.StatusForbidden, "Forbidden")
				return
			}
			roles, err := resolver.GetRolesByUserID(context.Background(), userID)
			if err != nil {
				SendError(ctx, fasthttp.StatusForbidden, "Forbidden")
				return
			}
			for _, role := range roles {
				if role.ID == tables.RoleIDSuperAdmin {
					next(ctx)
					return
				}
			}
			permission, mapped := managementRoutePermission(method, path)
			if !mapped {
				SendError(ctx, fasthttp.StatusForbidden, "Forbidden")
				return
			}
			for _, role := range roles {
				if authorization.Has(role.Permissions, permission) {
					next(ctx)
					return
				}
			}
			SendError(ctx, fasthttp.StatusForbidden, "Forbidden")
		}
	}
}

func authBypassed(ctx *fasthttp.RequestCtx) bool {
	bypassed, _ := ctx.UserValue(schemas.BifrostContextKeyAuthBypassed).(bool)
	return bypassed
}

func isTrustedLocalAdmin(ctx *fasthttp.RequestCtx) bool {
	admin, _ := ctx.UserValue(schemas.IsLocalAdminContextKey).(bool)
	return admin
}

func isCanonicalSelfServiceRoute(method, path string) bool {
	switch {
	case method == fasthttp.MethodPost && path == "/api/session/ws-ticket":
		return true
	case method == fasthttp.MethodGet && path == "/api/session/current-user":
		return true
	case method == fasthttp.MethodGet && path == "/api/session/sessions":
		return true
	case method == fasthttp.MethodPost && path == "/api/session/logout-all":
		return true
	case method == fasthttp.MethodPost && path == "/api/session/change-password":
		return true
	case method == fasthttp.MethodDelete && hasSinglePathSegment(path, "/api/session/sessions/"):
		return true
	case method == fasthttp.MethodGet && path == "/api/session/me/permissions":
		return true
	default:
		return false
	}
}

func managementRoutePermission(method, path string) (authorization.Permission, bool) {
	if strings.HasPrefix(path, "/api/auth/providers/") {
		suffix := strings.TrimPrefix(path, "/api/auth/providers/")
		parts := strings.Split(suffix, "/")
		if len(parts) == 2 && parts[0] != "" {
			switch {
			case parts[1] == "verify" && method == fasthttp.MethodPost:
				return authorization.PermissionUsersUpdate, true
			case parts[1] == "claims-preview" && method == fasthttp.MethodGet:
				return authorization.PermissionUsersRead, true
			}
		}
	}
	if path == "/api/governance/roles" {
		switch method {
		case fasthttp.MethodGet:
			return authorization.PermissionUsersRead, true
		case fasthttp.MethodPost:
			return authorization.PermissionUsersUpdate, true
		default:
			return "", false
		}
	}
	if strings.HasPrefix(path, "/api/governance/rbac/") {
		if method == fasthttp.MethodGet && (path == "/api/governance/rbac/resources" || path == "/api/governance/rbac/operations" || path == "/api/governance/rbac/permissions") {
			return authorization.PermissionUsersRead, true
		}
		return "", false
	}
	if path == "/api/governance/access-profiles" {
		switch method {
		case fasthttp.MethodGet:
			return authorization.PermissionAccessProfilesRead, true
		case fasthttp.MethodPost:
			return authorization.PermissionAccessProfilesCreate, true
		default:
			return "", false
		}
	}
	if strings.HasPrefix(path, "/api/governance/access-profiles/") {
		remainder := strings.TrimPrefix(path, "/api/governance/access-profiles/")
		if remainder != "" && !strings.Contains(remainder, "/") {
			switch method {
			case fasthttp.MethodGet:
				return authorization.PermissionAccessProfilesRead, true
			case fasthttp.MethodPut, fasthttp.MethodPatch:
				return authorization.PermissionAccessProfilesUpdate, true
			case fasthttp.MethodDelete:
				return authorization.PermissionAccessProfilesDelete, true
			}
		}
		return "", false
	}
	if path == "/api/governance/projects" {
		switch method {
		case fasthttp.MethodGet:
			return authorization.PermissionProjectsRead, true
		case fasthttp.MethodPost:
			return authorization.PermissionProjectsCreate, true
		default:
			return "", false
		}
	}
	if strings.HasPrefix(path, "/api/governance/projects/") {
		remainder := strings.TrimPrefix(path, "/api/governance/projects/")
		parts := strings.Split(remainder, "/")
		if len(parts) == 1 && parts[0] != "" {
			switch method {
			case fasthttp.MethodGet:
				return authorization.PermissionProjectsRead, true
			case fasthttp.MethodPut, fasthttp.MethodPatch:
				return authorization.PermissionProjectsUpdate, true
			case fasthttp.MethodDelete:
				return authorization.PermissionProjectsDelete, true
			}
		}
		if len(parts) == 2 && parts[0] != "" && parts[1] == "members" {
			switch method {
			case fasthttp.MethodGet:
				return authorization.PermissionProjectsRead, true
			case fasthttp.MethodPut:
				return authorization.PermissionProjectsAssign, true
			}
		}
		return "", false
	}
	if strings.HasPrefix(path, "/api/governance/virtual-keys/") {
		remainder := strings.TrimPrefix(path, "/api/governance/virtual-keys/")
		parts := strings.Split(remainder, "/")
		if len(parts) == 2 && parts[0] != "" && parts[1] == "users" && method == fasthttp.MethodGet {
			return authorization.PermissionVirtualKeysAssign, true
		}
		return "", false
	}
	if strings.HasPrefix(path, "/api/governance/roles/") {
		remainder := strings.TrimPrefix(path, "/api/governance/roles/")
		parts := strings.Split(remainder, "/")
		if len(parts) == 1 && parts[0] != "" {
			switch method {
			case fasthttp.MethodGet:
				return authorization.PermissionUsersRead, true
			case fasthttp.MethodPut, fasthttp.MethodPatch, fasthttp.MethodDelete:
				return authorization.PermissionUsersUpdate, true
			}
		}
		if len(parts) == 2 && parts[0] != "" && parts[1] == "permissions" {
			switch method {
			case fasthttp.MethodGet:
				return authorization.PermissionUsersRead, true
			case fasthttp.MethodPut:
				return authorization.PermissionUsersUpdate, true
			}
		}
		return "", false
	}
	if path == "/api/governance/business-units" {
		switch method {
		case fasthttp.MethodGet:
			return authorization.PermissionUsersRead, true
		case fasthttp.MethodPost:
			return authorization.PermissionUsersCreate, true
		default:
			return "", false
		}
	}
	if strings.HasPrefix(path, "/api/governance/business-units/") {
		remainder := strings.TrimPrefix(path, "/api/governance/business-units/")
		if remainder != "" && !strings.Contains(remainder, "/") {
			switch method {
			case fasthttp.MethodGet:
				return authorization.PermissionUsersRead, true
			case fasthttp.MethodPut, fasthttp.MethodPatch, fasthttp.MethodDelete:
				return authorization.PermissionUsersUpdate, true
			}
		}
		return "", false
	}
	if path == "/api/governance/users" {
		switch method {
		case fasthttp.MethodGet:
			return authorization.PermissionUsersRead, true
		case fasthttp.MethodPost:
			return authorization.PermissionUsersCreate, true
		default:
			return "", false
		}
	}
	if !strings.HasPrefix(path, "/api/governance/users/") {
		return "", false
	}
	remainder := strings.TrimPrefix(path, "/api/governance/users/")
	parts := strings.Split(remainder, "/")
	if len(parts) == 1 && parts[0] != "" {
		switch method {
		case fasthttp.MethodGet:
			return authorization.PermissionUsersRead, true
		case fasthttp.MethodPatch, fasthttp.MethodPut, fasthttp.MethodDelete:
			return authorization.PermissionUsersUpdate, true
		default:
			return "", false
		}
	}
	if len(parts) == 3 && parts[0] != "" && parts[1] == "identities" && parts[2] != "" && method == fasthttp.MethodDelete {
		return authorization.PermissionUsersUpdate, true
	}
	if len(parts) == 2 && parts[0] != "" && parts[1] == "business-units" {
		switch method {
		case fasthttp.MethodGet:
			return authorization.PermissionUsersRead, true
		case fasthttp.MethodPut:
			return authorization.PermissionUsersAssignRoles, true
		}
		return "", false
	}
	if len(parts) == 2 && parts[0] != "" && parts[1] == "access-profiles" {
		switch method {
		case fasthttp.MethodGet:
			return authorization.PermissionAccessProfilesRead, true
		case fasthttp.MethodPut:
			return authorization.PermissionAccessProfilesAssign, true
		}
		return "", false
	}
	if len(parts) == 2 && parts[0] != "" && parts[1] == "projects" {
		switch method {
		case fasthttp.MethodGet:
			return authorization.PermissionProjectsRead, true
		case fasthttp.MethodPut:
			return authorization.PermissionProjectsAssign, true
		}
		return "", false
	}
	if len(parts) == 2 && parts[0] != "" && parts[1] == "virtual-keys" {
		switch method {
		case fasthttp.MethodGet:
			return authorization.PermissionVirtualKeysAssign, true
		case fasthttp.MethodPut:
			return authorization.PermissionVirtualKeysAssign, true
		}
		return "", false
	}
	if len(parts) == 2 && parts[0] != "" && parts[1] == "effective-access" && method == fasthttp.MethodGet {
		return authorization.PermissionAccessProfilesRead, true
	}
	if len(parts) != 2 || parts[0] == "" {
		return "", false
	}
	switch {
	case parts[1] == "reset-password" && method == fasthttp.MethodPost:
		return authorization.PermissionUsersResetPassword, true
	case parts[1] == "revoke-sessions" && method == fasthttp.MethodPost:
		return authorization.PermissionUsersRevokeSessions, true
	case parts[1] == "roles" && method == fasthttp.MethodPut:
		return authorization.PermissionUsersAssignRoles, true
	case parts[1] == "teams" && method == fasthttp.MethodGet:
		return authorization.PermissionUsersRead, true
	case parts[1] == "teams" && method == fasthttp.MethodPut:
		return authorization.PermissionUsersAssignRoles, true
	case parts[1] == "identities" && method == fasthttp.MethodGet:
		return authorization.PermissionUsersRead, true
	default:
		return "", false
	}
}

func hasSinglePathSegment(path, prefix string) bool {
	value := strings.TrimPrefix(path, prefix)
	return value != path && value != "" && !strings.Contains(value, "/")
}
