package handlers

import (
	"context"
	"errors"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/authorization"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

type roleResolverStub struct {
	roles map[string][]tables.TableRole
	err   error
}

func (s roleResolverStub) GetRolesByUserID(context.Context, string) ([]tables.TableRole, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.roles["user"], nil
}

func TestIdentityAuthorizationMiddlewareDeniesUnmappedCanonicalManagementRoutes(t *testing.T) {
	viewer := tables.TableRole{ID: authorization.RoleIDViewer, Permissions: []string{string(authorization.PermissionUsersRead), string(authorization.PermissionUserAnalyticsRead)}}
	superAdmin := tables.TableRole{ID: tables.RoleIDSuperAdmin}

	tests := []struct {
		name       string
		method     string
		path       string
		roles      []tables.TableRole
		userID     string
		bypassed   bool
		wantCalled bool
		wantStatus int
	}{
		{name: "viewer reads users", method: fasthttp.MethodGet, path: "/api/governance/users", roles: []tables.TableRole{viewer}, userID: "user", wantCalled: true, wantStatus: fasthttp.StatusOK},
		{name: "profile manager reads profiles", method: fasthttp.MethodGet, path: "/api/governance/access-profiles", roles: []tables.TableRole{{ID: "profiles", Permissions: []string{string(authorization.PermissionAccessProfilesRead)}}}, userID: "user", wantCalled: true, wantStatus: fasthttp.StatusOK},
		{name: "profile manager creates profiles", method: fasthttp.MethodPost, path: "/api/governance/access-profiles", roles: []tables.TableRole{{ID: "profiles", Permissions: []string{string(authorization.PermissionAccessProfilesCreate)}}}, userID: "user", wantCalled: true, wantStatus: fasthttp.StatusOK},
		{name: "project manager reads projects", method: fasthttp.MethodGet, path: "/api/governance/projects", roles: []tables.TableRole{{ID: "projects", Permissions: []string{string(authorization.PermissionProjectsRead)}}}, userID: "user", wantCalled: true, wantStatus: fasthttp.StatusOK},
		{name: "project manager assigns members", method: fasthttp.MethodPut, path: "/api/governance/projects/project-1/members", roles: []tables.TableRole{{ID: "projects", Permissions: []string{string(authorization.PermissionProjectsAssign)}}}, userID: "user", wantCalled: true, wantStatus: fasthttp.StatusOK},
		{name: "key manager assigns user keys", method: fasthttp.MethodPut, path: "/api/governance/users/user/virtual-keys", roles: []tables.TableRole{{ID: "keys", Permissions: []string{string(authorization.PermissionVirtualKeysAssign)}}}, userID: "user", wantCalled: true, wantStatus: fasthttp.StatusOK},
		{name: "key manager lists key users", method: fasthttp.MethodGet, path: "/api/governance/virtual-keys/key-1/users", roles: []tables.TableRole{{ID: "keys", Permissions: []string{string(authorization.PermissionVirtualKeysAssign)}}}, userID: "user", wantCalled: true, wantStatus: fasthttp.StatusOK},
		{name: "viewer reads own analytics", method: fasthttp.MethodGet, path: "/api/governance/users/user/analytics", roles: []tables.TableRole{viewer}, userID: "user", wantCalled: true, wantStatus: fasthttp.StatusOK},
		{name: "analytics write is unmapped", method: fasthttp.MethodPost, path: "/api/governance/users/user/analytics", roles: []tables.TableRole{viewer}, userID: "user", wantStatus: fasthttp.StatusForbidden},
		{name: "viewer cannot create users", method: fasthttp.MethodPost, path: "/api/governance/users", roles: []tables.TableRole{viewer}, userID: "user", wantStatus: fasthttp.StatusForbidden},
		{name: "viewer cannot access unmapped route", method: fasthttp.MethodGet, path: "/api/config", roles: []tables.TableRole{viewer}, userID: "user", wantStatus: fasthttp.StatusForbidden},
		{name: "super admin retains management access", method: fasthttp.MethodGet, path: "/api/config", roles: []tables.TableRole{superAdmin}, userID: "user", wantCalled: true, wantStatus: fasthttp.StatusOK},
		{name: "canonical user manages own sessions", method: fasthttp.MethodGet, path: "/api/session/sessions", roles: nil, userID: "user", wantCalled: true, wantStatus: fasthttp.StatusOK},
		{name: "auth disabled bypass is preserved", method: fasthttp.MethodGet, path: "/api/config", roles: nil, bypassed: true, wantCalled: true, wantStatus: fasthttp.StatusOK},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := &fasthttp.RequestCtx{}
			ctx.Request.Header.SetMethod(test.method)
			ctx.Request.SetRequestURI(test.path)
			if test.userID != "" {
				ctx.SetUserValue(schemas.BifrostContextKeyUserID, test.userID)
			}
			if test.bypassed {
				ctx.SetUserValue(schemas.BifrostContextKeyAuthBypassed, true)
			}
			called := false
			resolver := roleResolverStub{roles: map[string][]tables.TableRole{"user": test.roles}}
			NewIdentityAuthorizationMiddleware(resolver)(func(ctx *fasthttp.RequestCtx) {
				called = true
				ctx.SetStatusCode(fasthttp.StatusOK)
			})(ctx)

			assert.Equal(t, test.wantCalled, called)
			assert.Equal(t, test.wantStatus, ctx.Response.StatusCode())
		})
	}
}

func TestIdentityAuthorizationMiddlewareFailsClosedWhenRoleLookupFails(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodGet)
	ctx.Request.SetRequestURI("/api/governance/users")
	ctx.SetUserValue(schemas.BifrostContextKeyUserID, "user")
	called := false
	NewIdentityAuthorizationMiddleware(roleResolverStub{err: errors.New("database unavailable")})(func(*fasthttp.RequestCtx) {
		called = true
	})(ctx)

	assert.False(t, called)
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
}
