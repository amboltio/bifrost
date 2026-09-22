package handlers

import (
	"context"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/valyala/fasthttp"
)

type rbacResolverStub struct{}

func (rbacResolverStub) GetRolesByUserID(context.Context, string) ([]tables.TableRole, error) {
	return []tables.TableRole{{ID: "viewer", Permissions: []string{"users.read"}}}, nil
}

func TestRBACHandlerCurrentUserPermissions(t *testing.T) {
	h := NewRBACHandler(rbacResolverStub{})
	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue(schemas.BifrostContextKeyUserID, "user-1")
	h.currentUserPermissions(ctx)
	if ctx.Response.StatusCode() != fasthttp.StatusOK {
		t.Fatalf("expected 200, got %d", ctx.Response.StatusCode())
	}
	if got := string(ctx.Response.Body()); got == "" || got == "{}" {
		t.Fatalf("expected permissions response, got %q", got)
	}
}

func TestRBACHandlerCatalogIsAvailable(t *testing.T) {
	h := NewRBACHandler(rbacResolverStub{})
	ctx := &fasthttp.RequestCtx{}
	h.permissionsCatalog(ctx)
	if ctx.Response.StatusCode() != fasthttp.StatusOK {
		t.Fatalf("expected 200, got %d", ctx.Response.StatusCode())
	}
	if body := string(ctx.Response.Body()); body == "" || body == "{}" {
		t.Fatalf("expected catalog response, got %q", body)
	}
}
