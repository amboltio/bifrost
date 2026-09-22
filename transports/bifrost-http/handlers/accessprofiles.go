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

// AccessProfilesHandler exposes the reusable policy and user-assignment
// surface. The handler deliberately returns only allow-list metadata; secrets
// and provider credentials never belong in an access profile.
type AccessProfilesHandler struct {
	store configstore.AccessProfileManagementStore
}

func NewAccessProfilesHandler(store configstore.ConfigStore) *AccessProfilesHandler {
	management, ok := store.(configstore.AccessProfileManagementStore)
	if !ok {
		return nil
	}
	return &AccessProfilesHandler{store: management}
}

func (h *AccessProfilesHandler) RegisterRoutes(r *router.Router, middlewares ...schemas.BifrostHTTPMiddleware) {
	r.GET("/api/governance/access-profiles", lib.ChainMiddlewares(h.list, middlewares...))
	r.POST("/api/governance/access-profiles", lib.ChainMiddlewares(h.create, middlewares...))
	r.GET("/api/governance/access-profiles/{id}", lib.ChainMiddlewares(h.get, middlewares...))
	r.PUT("/api/governance/access-profiles/{id}", lib.ChainMiddlewares(h.update, middlewares...))
	r.PATCH("/api/governance/access-profiles/{id}", lib.ChainMiddlewares(h.update, middlewares...))
	r.DELETE("/api/governance/access-profiles/{id}", lib.ChainMiddlewares(h.delete, middlewares...))
	r.GET("/api/governance/users/{id}/access-profiles", lib.ChainMiddlewares(h.listUserAssignments, middlewares...))
	r.PUT("/api/governance/users/{id}/access-profiles", lib.ChainMiddlewares(h.replaceUserAssignments, middlewares...))
	r.GET("/api/governance/users/{id}/effective-access", lib.ChainMiddlewares(h.effectiveAccess, middlewares...))
}

type accessProfileResponse struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	Enabled           bool     `json:"enabled"`
	AllowAllProviders bool     `json:"allow_all_providers"`
	AllowedProviders  []string `json:"allowed_providers"`
	AllowedModels     []string `json:"allowed_models"`
	AllowedMCPTools   []string `json:"allowed_mcp_tools"`
	CreatedByUserID   *string  `json:"created_by_user_id,omitempty"`
	CreatedAt         string   `json:"created_at"`
	UpdatedAt         string   `json:"updated_at"`
}

func newAccessProfileResponse(profile tables.TableAccessProfile) accessProfileResponse {
	return accessProfileResponse{ID: profile.ID, Name: profile.Name, Description: profile.Description, Enabled: profile.Enabled, AllowAllProviders: profile.AllowAllProviders, AllowedProviders: profile.AllowedProviders, AllowedModels: profile.AllowedModels, AllowedMCPTools: profile.AllowedMCPTools, CreatedByUserID: profile.CreatedByUserID, CreatedAt: profile.CreatedAt.UTC().Format("2006-01-02T15:04:05.999Z07:00"), UpdatedAt: profile.UpdatedAt.UTC().Format("2006-01-02T15:04:05.999Z07:00")}
}

func (h *AccessProfilesHandler) list(ctx *fasthttp.RequestCtx) {
	params, ok := accessProfileQueryParams(ctx)
	if !ok {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid pagination")
		return
	}
	profiles, total, err := h.store.ListAccessProfiles(ctx, params)
	if h.writeError(ctx, err) {
		return
	}
	response := make([]accessProfileResponse, 0, len(profiles))
	for _, profile := range profiles {
		response = append(response, newAccessProfileResponse(profile))
	}
	SendJSON(ctx, map[string]any{"access_profiles": response, "total": total, "limit": params.Limit, "offset": params.Offset})
}

func (h *AccessProfilesHandler) get(ctx *fasthttp.RequestCtx) {
	id, _ := ctx.UserValue("id").(string)
	profile, err := h.store.GetAccessProfile(ctx, strings.TrimSpace(id))
	if h.writeError(ctx, err) {
		return
	}
	if profile == nil {
		SendError(ctx, fasthttp.StatusNotFound, "Access profile not found")
		return
	}
	SendJSON(ctx, newAccessProfileResponse(*profile))
}

type accessProfileRequest struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	Enabled           *bool    `json:"enabled"`
	AllowAllProviders bool     `json:"allow_all_providers"`
	AllowedProviders  []string `json:"allowed_providers"`
	AllowedModels     []string `json:"allowed_models"`
	AllowedMCPTools   []string `json:"allowed_mcp_tools"`
}

func (h *AccessProfilesHandler) create(ctx *fasthttp.RequestCtx) {
	if !allowSessionStateChange(ctx) {
		SendError(ctx, fasthttp.StatusForbidden, "Invalid request origin")
		return
	}
	var request accessProfileRequest
	if err := json.Unmarshal(ctx.PostBody(), &request); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid request payload")
		return
	}
	enabled := true
	if request.Enabled != nil {
		enabled = *request.Enabled
	}
	profile := &tables.TableAccessProfile{ID: strings.TrimSpace(request.ID), Name: strings.TrimSpace(request.Name), Description: strings.TrimSpace(request.Description), Enabled: enabled, AllowAllProviders: request.AllowAllProviders, AllowedProviders: request.AllowedProviders, AllowedModels: request.AllowedModels, AllowedMCPTools: request.AllowedMCPTools, CreatedByUserID: canonicalActorUserID(ctx)}
	if profile.ID == "" {
		profile.ID = uuid.NewString()
	}
	audit, outbox := h.audit(ctx, profile.ID, "governance.access_profile.created")
	created, err := h.store.CreateAccessProfileAudited(ctx, profile, audit, outbox)
	if h.writeError(ctx, err) {
		return
	}
	SendJSONWithStatus(ctx, newAccessProfileResponse(*created), fasthttp.StatusCreated)
}

func (h *AccessProfilesHandler) update(ctx *fasthttp.RequestCtx) {
	if !allowSessionStateChange(ctx) {
		SendError(ctx, fasthttp.StatusForbidden, "Invalid request origin")
		return
	}
	id, _ := ctx.UserValue("id").(string)
	current, err := h.store.GetAccessProfile(ctx, strings.TrimSpace(id))
	if h.writeError(ctx, err) {
		return
	}
	if current == nil {
		SendError(ctx, fasthttp.StatusNotFound, "Access profile not found")
		return
	}
	var request accessProfileRequest
	if err := json.Unmarshal(ctx.PostBody(), &request); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid request payload")
		return
	}
	name, description, enabled := current.Name, current.Description, current.Enabled
	if request.Name != "" {
		name = strings.TrimSpace(request.Name)
	}
	if request.Description != "" {
		description = strings.TrimSpace(request.Description)
	}
	if request.Enabled != nil {
		enabled = *request.Enabled
	}
	providers, models, mcpTools := current.AllowedProviders, current.AllowedModels, current.AllowedMCPTools
	if request.AllowedProviders != nil {
		providers = request.AllowedProviders
	}
	if request.AllowedModels != nil {
		models = request.AllowedModels
	}
	if request.AllowedMCPTools != nil {
		mcpTools = request.AllowedMCPTools
	}
	audit, outbox := h.audit(ctx, current.ID, "governance.access_profile.updated")
	updated, err := h.store.UpdateAccessProfileAudited(ctx, current.ID, name, description, enabled, request.AllowAllProviders, providers, models, mcpTools, audit, outbox)
	if h.writeError(ctx, err) {
		return
	}
	SendJSON(ctx, newAccessProfileResponse(*updated))
}

func (h *AccessProfilesHandler) delete(ctx *fasthttp.RequestCtx) {
	if !allowSessionStateChange(ctx) {
		SendError(ctx, fasthttp.StatusForbidden, "Invalid request origin")
		return
	}
	id, _ := ctx.UserValue("id").(string)
	audit, outbox := h.audit(ctx, strings.TrimSpace(id), "governance.access_profile.deleted")
	if h.writeError(ctx, h.store.DeleteAccessProfileAudited(ctx, strings.TrimSpace(id), audit, outbox)) {
		return
	}
	ctx.SetStatusCode(fasthttp.StatusNoContent)
}

func (h *AccessProfilesHandler) listUserAssignments(ctx *fasthttp.RequestCtx) {
	userID, _ := ctx.UserValue("id").(string)
	assignments, err := h.store.ListUserAccessProfileAssignments(ctx, strings.TrimSpace(userID))
	if h.writeError(ctx, err) {
		return
	}
	profiles := make([]accessProfileResponse, 0, len(assignments))
	for _, assignment := range assignments {
		profile, getErr := h.store.GetAccessProfile(ctx, assignment.AccessProfileID)
		if getErr != nil {
			h.writeError(ctx, getErr)
			return
		}
		if profile != nil {
			profiles = append(profiles, newAccessProfileResponse(*profile))
		}
	}
	SendJSON(ctx, map[string]any{"access_profiles": profiles, "assignments": assignments})
}

func (h *AccessProfilesHandler) replaceUserAssignments(ctx *fasthttp.RequestCtx) {
	if !allowSessionStateChange(ctx) {
		SendError(ctx, fasthttp.StatusForbidden, "Invalid request origin")
		return
	}
	userID, _ := ctx.UserValue("id").(string)
	request := struct {
		AccessProfileIDs []string `json:"access_profile_ids"`
	}{}
	if err := json.Unmarshal(ctx.PostBody(), &request); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid request payload")
		return
	}
	audit, outbox := h.audit(ctx, strings.TrimSpace(userID), "governance.user.access_profiles_updated")
	if h.writeError(ctx, h.store.ReplaceManualUserAccessProfilesAudited(ctx, strings.TrimSpace(userID), request.AccessProfileIDs, canonicalActorUserID(ctx), audit, outbox)) {
		return
	}
	h.listUserAssignments(ctx)
}

func (h *AccessProfilesHandler) effectiveAccess(ctx *fasthttp.RequestCtx) {
	userID, _ := ctx.UserValue("id").(string)
	assignments, err := h.store.ListUserAccessProfileAssignments(ctx, strings.TrimSpace(userID))
	if h.writeError(ctx, err) {
		return
	}
	providers, models, tools := map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}
	profileIDs := make([]string, 0, len(assignments))
	allowAllProviders := false
	for _, assignment := range assignments {
		profile, getErr := h.store.GetAccessProfile(ctx, assignment.AccessProfileID)
		if getErr != nil {
			h.writeError(ctx, getErr)
			return
		}
		if profile == nil || !profile.Enabled {
			continue
		}
		profileIDs = append(profileIDs, profile.ID)
		allowAllProviders = allowAllProviders || profile.AllowAllProviders
		for _, value := range profile.AllowedProviders {
			providers[value] = struct{}{}
		}
		for _, value := range profile.AllowedModels {
			models[value] = struct{}{}
		}
		for _, value := range profile.AllowedMCPTools {
			tools[value] = struct{}{}
		}
	}
	SendJSON(ctx, map[string]any{"user_id": strings.TrimSpace(userID), "profile_ids": profileIDs, "allow_all_providers": allowAllProviders, "allowed_providers": sortedSet(providers), "allowed_models": sortedSet(models), "allowed_mcp_tools": sortedSet(tools)})
}

func sortedSet(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	return configstoreSorted(result)
}

func configstoreSorted(values []string) []string {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
	return values
}

func (h *AccessProfilesHandler) audit(ctx *fasthttp.RequestCtx, targetID, action string) (*tables.TableAuditEvent, *tables.TableOutboxEvent) {
	eventID := uuid.NewString()
	actor := "legacy:local_admin"
	if userID := canonicalActorUserID(ctx); userID != nil {
		actor = "user:" + *userID
	}
	return &tables.TableAuditEvent{ID: eventID, ActorPrincipal: actor, TargetType: "access_profile", TargetID: &targetID, Action: action, OccurredAt: time.Now().UTC()}, &tables.TableOutboxEvent{Topic: "governance.access_profile.changed", DeduplicationKey: "governance.access_profile:" + eventID, Payload: map[string]any{"access_profile_id": targetID, "action": action}}
}

func accessProfileQueryParams(ctx *fasthttp.RequestCtx) (configstore.AccessProfileQueryParams, bool) {
	params := configstore.AccessProfileQueryParams{Search: string(ctx.QueryArgs().Peek("search")), Limit: 50}
	if raw := ctx.QueryArgs().Peek("limit"); len(raw) > 0 {
		value, err := fasthttp.ParseUint(raw)
		if err != nil || value == 0 || value > 100 {
			return configstore.AccessProfileQueryParams{}, false
		}
		params.Limit = int(value)
	}
	if raw := ctx.QueryArgs().Peek("offset"); len(raw) > 0 {
		value, err := fasthttp.ParseUint(raw)
		if err != nil {
			return configstore.AccessProfileQueryParams{}, false
		}
		params.Offset = int(value)
	}
	return params, true
}

func (h *AccessProfilesHandler) writeError(ctx *fasthttp.RequestCtx, err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, configstore.ErrNotFound):
		SendError(ctx, fasthttp.StatusNotFound, "Access profile or user not found")
	case errors.Is(err, configstore.ErrAlreadyExists):
		SendError(ctx, fasthttp.StatusConflict, "An access profile with that name already exists")
	case errors.Is(err, configstore.ErrAccessProfileInUse):
		SendError(ctx, fasthttp.StatusConflict, "Access profile still has active assignments")
	default:
		logger.Error(fmt.Sprintf("access profile operation failed: %v", err))
		SendError(ctx, fasthttp.StatusInternalServerError, "Access profile operation failed")
	}
	return true
}
