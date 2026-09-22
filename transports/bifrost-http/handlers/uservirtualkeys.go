package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fasthttp/router"
	"github.com/google/uuid"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/configstore"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/maximhq/bifrost/transports/bifrost-http/lib"
	"github.com/valyala/fasthttp"
)

type UserVirtualKeysHandler struct {
	store configstore.UserVirtualKeyAssignmentStore
}

func NewUserVirtualKeysHandler(store configstore.ConfigStore) *UserVirtualKeysHandler {
	management, ok := store.(configstore.UserVirtualKeyAssignmentStore)
	if !ok {
		return nil
	}
	return &UserVirtualKeysHandler{store: management}
}

func (h *UserVirtualKeysHandler) RegisterRoutes(r *router.Router, middlewares ...schemas.BifrostHTTPMiddleware) {
	r.GET("/api/governance/users/{id}/virtual-keys", lib.ChainMiddlewares(h.listUser, middlewares...))
	r.PUT("/api/governance/users/{id}/virtual-keys", lib.ChainMiddlewares(h.replaceUser, middlewares...))
	r.GET("/api/governance/virtual-keys/{id}/users", lib.ChainMiddlewares(h.listKeyUsers, middlewares...))
}

func (h *UserVirtualKeysHandler) listUser(ctx *fasthttp.RequestCtx) {
	userID, _ := ctx.UserValue("id").(string)
	assignments, err := h.store.ListUserVirtualKeyAssignments(ctx, strings.TrimSpace(userID))
	if h.writeError(ctx, err) {
		return
	}
	SendJSON(ctx, map[string]any{"assignments": assignments})
}

func (h *UserVirtualKeysHandler) replaceUser(ctx *fasthttp.RequestCtx) {
	if !allowSessionStateChange(ctx) {
		SendError(ctx, fasthttp.StatusForbidden, "Invalid request origin")
		return
	}
	userID, _ := ctx.UserValue("id").(string)
	request := struct {
		VirtualKeyIDs []string `json:"virtual_key_ids"`
	}{}
	if err := json.Unmarshal(ctx.PostBody(), &request); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid request payload")
		return
	}
	audit, outbox := h.audit(ctx, strings.TrimSpace(userID), "governance.user.virtual_keys_updated")
	if h.writeError(ctx, h.store.ReplaceManualUserVirtualKeyAssignmentsAudited(ctx, strings.TrimSpace(userID), request.VirtualKeyIDs, canonicalActorUserID(ctx), audit, outbox)) {
		return
	}
	h.listUser(ctx)
}

func (h *UserVirtualKeysHandler) listKeyUsers(ctx *fasthttp.RequestCtx) {
	virtualKeyID, _ := ctx.UserValue("id").(string)
	assignments, err := h.store.ListVirtualKeyUserAssignments(ctx, strings.TrimSpace(virtualKeyID))
	if h.writeError(ctx, err) {
		return
	}
	SendJSON(ctx, map[string]any{"assignments": assignments})
}

func (h *UserVirtualKeysHandler) audit(ctx *fasthttp.RequestCtx, targetID, action string) (*tables.TableAuditEvent, *tables.TableOutboxEvent) {
	eventID := uuid.NewString()
	actor := "legacy:local_admin"
	if userID := canonicalActorUserID(ctx); userID != nil {
		actor = "user:" + *userID
	}
	return &tables.TableAuditEvent{ID: eventID, ActorPrincipal: actor, TargetType: "user_virtual_key_assignment", TargetID: &targetID, Action: action, OccurredAt: time.Now().UTC()}, &tables.TableOutboxEvent{Topic: "governance.user_virtual_key.changed", DeduplicationKey: "governance.user_virtual_key:" + eventID, Payload: map[string]any{"user_id": targetID, "action": action}}
}

func (h *UserVirtualKeysHandler) writeError(ctx *fasthttp.RequestCtx, err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, configstore.ErrNotFound):
		SendError(ctx, fasthttp.StatusNotFound, "User or virtual key not found")
	case errors.Is(err, configstore.ErrAlreadyExists):
		SendError(ctx, fasthttp.StatusConflict, "Virtual key assignment already exists")
	default:
		logger.Error(fmt.Sprintf("virtual key assignment failed: %v", err))
		SendError(ctx, fasthttp.StatusInternalServerError, "Virtual key assignment failed")
	}
	return true
}
