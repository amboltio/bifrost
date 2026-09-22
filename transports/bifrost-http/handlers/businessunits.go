package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
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

type BusinessUnitsHandler struct {
	store configstore.BusinessUnitManagementStore
	now   func() time.Time
}

func NewBusinessUnitsHandler(store any) *BusinessUnitsHandler {
	managementStore, ok := store.(configstore.BusinessUnitManagementStore)
	if !ok || managementStore == nil {
		return nil
	}
	return &BusinessUnitsHandler{store: managementStore, now: time.Now}
}

func (h *BusinessUnitsHandler) RegisterRoutes(r *router.Router, middlewares ...schemas.BifrostHTTPMiddleware) {
	r.GET("/api/governance/business-units", lib.ChainMiddlewares(h.list, middlewares...))
	r.POST("/api/governance/business-units", lib.ChainMiddlewares(h.create, middlewares...))
	r.GET("/api/governance/business-units/{id}", lib.ChainMiddlewares(h.get, middlewares...))
	r.PUT("/api/governance/business-units/{id}", lib.ChainMiddlewares(h.update, middlewares...))
	r.PATCH("/api/governance/business-units/{id}", lib.ChainMiddlewares(h.update, middlewares...))
	r.DELETE("/api/governance/business-units/{id}", lib.ChainMiddlewares(h.delete, middlewares...))
	r.GET("/api/governance/users/{id}/business-units", lib.ChainMiddlewares(h.listUserMemberships, middlewares...))
	r.PUT("/api/governance/users/{id}/business-units", lib.ChainMiddlewares(h.replaceUserMemberships, middlewares...))
}

type businessUnitResponse struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Description     string    `json:"description"`
	CustomerID      *string   `json:"customer_id,omitempty"`
	CreatedByUserID *string   `json:"created_by_user_id,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

func newBusinessUnitResponse(unit tables.TableBusinessUnit) businessUnitResponse {
	return businessUnitResponse{ID: unit.ID, Name: unit.Name, Description: unit.Description, CustomerID: unit.CustomerID, CreatedByUserID: unit.CreatedByUserID, CreatedAt: unit.CreatedAt, UpdatedAt: unit.UpdatedAt}
}

func (h *BusinessUnitsHandler) list(ctx *fasthttp.RequestCtx) {
	params, ok := businessUnitQueryParams(ctx)
	if !ok {
		SendError(ctx, fasthttp.StatusBadRequest, "limit and offset must be non-negative integers")
		return
	}
	units, total, err := h.store.ListBusinessUnits(ctx, params)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to list business units")
		return
	}
	response := make([]businessUnitResponse, 0, len(units))
	for _, unit := range units {
		response = append(response, newBusinessUnitResponse(unit))
	}
	SendJSON(ctx, map[string]any{"business_units": response, "total": total, "limit": params.Limit, "offset": params.Offset})
}

func (h *BusinessUnitsHandler) get(ctx *fasthttp.RequestCtx) {
	id, _ := ctx.UserValue("id").(string)
	unit, err := h.store.GetBusinessUnit(ctx, strings.TrimSpace(id))
	if h.writeError(ctx, err) {
		return
	}
	if unit == nil {
		SendError(ctx, fasthttp.StatusNotFound, "Business unit not found")
		return
	}
	SendJSON(ctx, newBusinessUnitResponse(*unit))
}

func (h *BusinessUnitsHandler) create(ctx *fasthttp.RequestCtx) {
	if !allowSessionStateChange(ctx) {
		SendError(ctx, fasthttp.StatusForbidden, "Invalid request origin")
		return
	}
	request := struct {
		ID          string  `json:"id"`
		Name        string  `json:"name"`
		Description string  `json:"description"`
		CustomerID  *string `json:"customer_id"`
	}{}
	if err := json.Unmarshal(ctx.PostBody(), &request); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid request payload")
		return
	}
	unit := &tables.TableBusinessUnit{ID: strings.TrimSpace(request.ID), Name: strings.TrimSpace(request.Name), Description: strings.TrimSpace(request.Description), CustomerID: request.CustomerID, CreatedByUserID: canonicalActorUserID(ctx)}
	if unit.ID == "" {
		unit.ID = uuid.NewString()
	}
	audit, outbox := h.audit(ctx, unit.ID, "identity.business_unit.created", map[string]any{"name": unit.Name})
	created, err := h.store.CreateBusinessUnitAudited(ctx, unit, audit, outbox)
	if h.writeError(ctx, err) {
		return
	}
	SendJSONWithStatus(ctx, newBusinessUnitResponse(*created), fasthttp.StatusCreated)
}

func (h *BusinessUnitsHandler) update(ctx *fasthttp.RequestCtx) {
	if !allowSessionStateChange(ctx) {
		SendError(ctx, fasthttp.StatusForbidden, "Invalid request origin")
		return
	}
	id, _ := ctx.UserValue("id").(string)
	current, err := h.store.GetBusinessUnit(ctx, strings.TrimSpace(id))
	if h.writeError(ctx, err) {
		return
	}
	if current == nil {
		SendError(ctx, fasthttp.StatusNotFound, "Business unit not found")
		return
	}
	request := struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
		CustomerID  *string `json:"customer_id"`
	}{}
	if err := json.Unmarshal(ctx.PostBody(), &request); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid request payload")
		return
	}
	name, description, customerID := current.Name, current.Description, current.CustomerID
	if request.Name != nil {
		name = strings.TrimSpace(*request.Name)
	}
	if request.Description != nil {
		description = strings.TrimSpace(*request.Description)
	}
	if request.CustomerID != nil {
		customerID = request.CustomerID
	}
	audit, outbox := h.audit(ctx, current.ID, "identity.business_unit.updated", map[string]any{"name": name, "description": description})
	updated, err := h.store.UpdateBusinessUnitAudited(ctx, current.ID, name, description, customerID, audit, outbox)
	if h.writeError(ctx, err) {
		return
	}
	SendJSON(ctx, newBusinessUnitResponse(*updated))
}

func (h *BusinessUnitsHandler) delete(ctx *fasthttp.RequestCtx) {
	if !allowSessionStateChange(ctx) {
		SendError(ctx, fasthttp.StatusForbidden, "Invalid request origin")
		return
	}
	id, _ := ctx.UserValue("id").(string)
	audit, outbox := h.audit(ctx, strings.TrimSpace(id), "identity.business_unit.deleted", nil)
	if h.writeError(ctx, h.store.DeleteBusinessUnitAudited(ctx, strings.TrimSpace(id), audit, outbox)) {
		return
	}
	ctx.SetStatusCode(fasthttp.StatusNoContent)
}

func (h *BusinessUnitsHandler) listUserMemberships(ctx *fasthttp.RequestCtx) {
	userID, _ := ctx.UserValue("id").(string)
	memberships, err := h.store.ListUserBusinessUnitMemberships(ctx, strings.TrimSpace(userID))
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to list user business units")
		return
	}
	SendJSON(ctx, map[string]any{"business_units": memberships})
}

func (h *BusinessUnitsHandler) replaceUserMemberships(ctx *fasthttp.RequestCtx) {
	if !allowSessionStateChange(ctx) {
		SendError(ctx, fasthttp.StatusForbidden, "Invalid request origin")
		return
	}
	userID, _ := ctx.UserValue("id").(string)
	request := struct {
		BusinessUnitIDs []string `json:"business_unit_ids"`
	}{}
	if err := json.Unmarshal(ctx.PostBody(), &request); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid request payload")
		return
	}
	audit, outbox := h.audit(ctx, strings.TrimSpace(userID), "identity.user.business_units_updated", map[string]any{"business_unit_ids": request.BusinessUnitIDs})
	if h.writeError(ctx, h.store.ReplaceManualUserBusinessUnitMembershipsAudited(ctx, strings.TrimSpace(userID), request.BusinessUnitIDs, canonicalActorUserID(ctx), audit, outbox)) {
		return
	}
	h.listUserMemberships(ctx)
}

func businessUnitQueryParams(ctx *fasthttp.RequestCtx) (configstore.BusinessUnitQueryParams, bool) {
	params := configstore.BusinessUnitQueryParams{Search: string(ctx.QueryArgs().Peek("search")), Limit: 50}
	if raw := ctx.QueryArgs().Peek("limit"); len(raw) > 0 {
		value, err := strconv.Atoi(string(raw))
		if err != nil || value <= 0 {
			return configstore.BusinessUnitQueryParams{}, false
		}
		params.Limit = value
	}
	if raw := ctx.QueryArgs().Peek("offset"); len(raw) > 0 {
		value, err := strconv.Atoi(string(raw))
		if err != nil || value < 0 {
			return configstore.BusinessUnitQueryParams{}, false
		}
		params.Offset = value
	}
	return params, true
}

func (h *BusinessUnitsHandler) audit(ctx *fasthttp.RequestCtx, targetID, action string, changed map[string]any) (*tables.TableAuditEvent, *tables.TableOutboxEvent) {
	eventID := uuid.NewString()
	actor := "legacy:local_admin"
	if userID := canonicalActorUserID(ctx); userID != nil {
		actor = "user:" + *userID
	}
	return &tables.TableAuditEvent{ID: eventID, ActorPrincipal: actor, TargetType: "business_unit", TargetID: &targetID, Action: action, OccurredAt: h.now().UTC(), ChangedFields: changed}, &tables.TableOutboxEvent{Topic: "identity.business_unit.changed", DeduplicationKey: "identity.business_unit:" + eventID, Payload: map[string]any{"business_unit_id": targetID, "action": action}}
}

func (h *BusinessUnitsHandler) writeError(ctx *fasthttp.RequestCtx, err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, configstore.ErrNotFound):
		SendError(ctx, fasthttp.StatusNotFound, "Business unit or user not found")
	case errors.Is(err, configstore.ErrAlreadyExists):
		SendError(ctx, fasthttp.StatusConflict, "A business unit with that name already exists")
	case errors.Is(err, configstore.ErrBusinessUnitInUse):
		SendError(ctx, fasthttp.StatusConflict, "Business unit still has active memberships")
	default:
		logger.Error(fmt.Sprintf("business unit operation failed: %v", err))
		SendError(ctx, fasthttp.StatusInternalServerError, "Business unit operation failed")
	}
	return true
}
