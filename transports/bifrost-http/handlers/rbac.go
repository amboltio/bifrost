package handlers

import (
	"context"
	"sort"
	"strings"

	"github.com/fasthttp/router"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/authorization"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/maximhq/bifrost/transports/bifrost-http/lib"
	"github.com/valyala/fasthttp"
)

// RBACHandler publishes the permission catalog and the effective permissions
// for the authenticated canonical user. The catalog is generated from the
// same typed constants used by route enforcement.
type RBACHandler struct {
	resolver UserRoleResolver
}

func NewRBACHandler(resolver UserRoleResolver) *RBACHandler {
	if resolver == nil {
		return nil
	}
	return &RBACHandler{resolver: resolver}
}

func (h *RBACHandler) RegisterRoutes(r *router.Router, middlewares ...schemas.BifrostHTTPMiddleware) {
	r.GET("/api/governance/rbac/resources", lib.ChainMiddlewares(h.resources, middlewares...))
	r.GET("/api/governance/rbac/operations", lib.ChainMiddlewares(h.operations, middlewares...))
	r.GET("/api/governance/rbac/permissions", lib.ChainMiddlewares(h.permissionsCatalog, middlewares...))
	r.GET("/api/session/me/permissions", lib.ChainMiddlewares(h.currentUserPermissions, middlewares...))
}

func (h *RBACHandler) resources(ctx *fasthttp.RequestCtx) {
	seen := map[string]struct{}{}
	resources := make([]string, 0)
	for _, permission := range authorization.Catalog() {
		parts := strings.SplitN(string(permission), ".", 2)
		if len(parts) != 2 {
			continue
		}
		if _, ok := seen[parts[0]]; ok {
			continue
		}
		seen[parts[0]] = struct{}{}
		resources = append(resources, parts[0])
	}
	sort.Strings(resources)
	SendJSON(ctx, map[string]any{"resources": resources})
}

func (h *RBACHandler) operations(ctx *fasthttp.RequestCtx) {
	seen := map[string]struct{}{}
	operations := make([]string, 0)
	for _, permission := range authorization.Catalog() {
		parts := strings.SplitN(string(permission), ".", 2)
		if len(parts) != 2 {
			continue
		}
		if _, ok := seen[parts[1]]; ok {
			continue
		}
		seen[parts[1]] = struct{}{}
		operations = append(operations, parts[1])
	}
	sort.Strings(operations)
	SendJSON(ctx, map[string]any{"operations": operations})
}

func (h *RBACHandler) permissionsCatalog(ctx *fasthttp.RequestCtx) {
	permissions := make([]map[string]string, 0, len(authorization.Catalog()))
	for _, permission := range authorization.Catalog() {
		parts := strings.SplitN(string(permission), ".", 2)
		if len(parts) != 2 {
			continue
		}
		permissions = append(permissions, map[string]string{"id": string(permission), "resource": parts[0], "operation": parts[1]})
	}
	SendJSON(ctx, map[string]any{"permissions": permissions})
}

func (h *RBACHandler) currentUserPermissions(ctx *fasthttp.RequestCtx) {
	userID, _ := ctx.UserValue(schemas.BifrostContextKeyUserID).(string)
	userID = strings.TrimSpace(userID)
	if userID == "" {
		SendError(ctx, fasthttp.StatusUnauthorized, "Unauthorized")
		return
	}
	roles, err := h.resolver.GetRolesByUserID(context.Background(), userID)
	if err != nil {
		SendError(ctx, fasthttp.StatusForbidden, "Forbidden")
		return
	}
	permissions := make(map[string]struct{})
	for _, role := range roles {
		if role.ID == tables.RoleIDSuperAdmin {
			for _, permission := range authorization.Catalog() {
				permissions[string(permission)] = struct{}{}
			}
			break
		}
		for _, permission := range role.Permissions {
			permissions[permission] = struct{}{}
		}
	}
	result := make([]string, 0, len(permissions))
	for permission := range permissions {
		result = append(result, permission)
	}
	sort.Strings(result)
	SendJSON(ctx, map[string]any{"user_id": userID, "permissions": result})
}
