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

type ProjectsHandler struct {
	store configstore.ProjectManagementStore
}

func NewProjectsHandler(store configstore.ConfigStore) *ProjectsHandler {
	management, ok := store.(configstore.ProjectManagementStore)
	if !ok {
		return nil
	}
	return &ProjectsHandler{store: management}
}

func (h *ProjectsHandler) RegisterRoutes(r *router.Router, middlewares ...schemas.BifrostHTTPMiddleware) {
	r.GET("/api/governance/projects", lib.ChainMiddlewares(h.list, middlewares...))
	r.POST("/api/governance/projects", lib.ChainMiddlewares(h.create, middlewares...))
	r.GET("/api/governance/projects/{id}", lib.ChainMiddlewares(h.get, middlewares...))
	r.PUT("/api/governance/projects/{id}", lib.ChainMiddlewares(h.update, middlewares...))
	r.PATCH("/api/governance/projects/{id}", lib.ChainMiddlewares(h.update, middlewares...))
	r.DELETE("/api/governance/projects/{id}", lib.ChainMiddlewares(h.delete, middlewares...))
	r.GET("/api/governance/projects/{id}/members", lib.ChainMiddlewares(h.listMembers, middlewares...))
	r.PUT("/api/governance/projects/{id}/members", lib.ChainMiddlewares(h.replaceMembers, middlewares...))
}

type projectResponse struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	Enabled           bool     `json:"enabled"`
	ExpiresAt         string   `json:"expires_at,omitempty"`
	AccessRule        string   `json:"access_rule"`
	MembershipMode    string   `json:"membership_mode"`
	AccountingMode    string   `json:"accounting_mode"`
	SplitPolicy       string   `json:"split_policy"`
	AllowAllProviders bool     `json:"allow_all_providers"`
	AllowedProviders  []string `json:"allowed_providers"`
	AllowedModels     []string `json:"allowed_models"`
	CreatedByUserID   *string  `json:"created_by_user_id,omitempty"`
	CreatedAt         string   `json:"created_at"`
	UpdatedAt         string   `json:"updated_at"`
}

func newProjectResponse(project tables.TableProject) projectResponse {
	response := projectResponse{ID: project.ID, Name: project.Name, Description: project.Description, Enabled: project.Enabled, AccessRule: project.AccessRule, MembershipMode: project.MembershipMode, AccountingMode: project.AccountingMode, SplitPolicy: project.SplitPolicy, AllowAllProviders: project.AllowAllProviders, AllowedProviders: project.AllowedProviders, AllowedModels: project.AllowedModels, CreatedByUserID: project.CreatedByUserID, CreatedAt: project.CreatedAt.UTC().Format(time.RFC3339Nano), UpdatedAt: project.UpdatedAt.UTC().Format(time.RFC3339Nano)}
	if project.ExpiresAt != nil {
		response.ExpiresAt = project.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	return response
}

type projectRequest struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	Enabled           *bool    `json:"enabled"`
	ExpiresAt         *string  `json:"expires_at"`
	AccessRule        string   `json:"access_rule"`
	MembershipMode    string   `json:"membership_mode"`
	AccountingMode    string   `json:"accounting_mode"`
	SplitPolicy       string   `json:"split_policy"`
	AllowAllProviders *bool    `json:"allow_all_providers"`
	AllowedProviders  []string `json:"allowed_providers"`
	AllowedModels     []string `json:"allowed_models"`
}

func parseProjectExpiry(value *string) (*time.Time, error) {
	if value == nil || strings.TrimSpace(*value) == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(*value))
	if err != nil {
		return nil, fmt.Errorf("expires_at must be RFC3339")
	}
	return &parsed, nil
}

func (h *ProjectsHandler) list(ctx *fasthttp.RequestCtx) {
	params, ok := projectQueryParams(ctx)
	if !ok {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid pagination")
		return
	}
	projects, total, err := h.store.ListProjects(ctx, params)
	if h.writeError(ctx, err) {
		return
	}
	response := make([]projectResponse, 0, len(projects))
	for _, project := range projects {
		response = append(response, newProjectResponse(project))
	}
	SendJSON(ctx, map[string]any{"projects": response, "total": total, "limit": params.Limit, "offset": params.Offset})
}

func (h *ProjectsHandler) get(ctx *fasthttp.RequestCtx) {
	id, _ := ctx.UserValue("id").(string)
	project, err := h.store.GetProject(ctx, strings.TrimSpace(id))
	if h.writeError(ctx, err) {
		return
	}
	if project == nil {
		SendError(ctx, fasthttp.StatusNotFound, "Project not found")
		return
	}
	SendJSON(ctx, newProjectResponse(*project))
}

func (h *ProjectsHandler) create(ctx *fasthttp.RequestCtx) {
	if !allowSessionStateChange(ctx) {
		SendError(ctx, fasthttp.StatusForbidden, "Invalid request origin")
		return
	}
	var request projectRequest
	if err := json.Unmarshal(ctx.PostBody(), &request); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid request payload")
		return
	}
	expiresAt, err := parseProjectExpiry(request.ExpiresAt)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}
	enabled := true
	if request.Enabled != nil {
		enabled = *request.Enabled
	}
	allowAllProviders := false
	if request.AllowAllProviders != nil {
		allowAllProviders = *request.AllowAllProviders
	}
	project := &tables.TableProject{ID: strings.TrimSpace(request.ID), Name: request.Name, Description: request.Description, Enabled: enabled, ExpiresAt: expiresAt, AccessRule: request.AccessRule, MembershipMode: request.MembershipMode, AccountingMode: request.AccountingMode, SplitPolicy: request.SplitPolicy, AllowAllProviders: allowAllProviders, AllowedProviders: request.AllowedProviders, AllowedModels: request.AllowedModels, CreatedByUserID: canonicalActorUserID(ctx)}
	audit, outbox := h.audit(ctx, project.ID, "governance.project.created")
	created, err := h.store.CreateProjectAudited(ctx, project, audit, outbox)
	if h.writeError(ctx, err) {
		return
	}
	SendJSONWithStatus(ctx, newProjectResponse(*created), fasthttp.StatusCreated)
}

func (h *ProjectsHandler) update(ctx *fasthttp.RequestCtx) {
	if !allowSessionStateChange(ctx) {
		SendError(ctx, fasthttp.StatusForbidden, "Invalid request origin")
		return
	}
	id, _ := ctx.UserValue("id").(string)
	current, err := h.store.GetProject(ctx, strings.TrimSpace(id))
	if h.writeError(ctx, err) {
		return
	}
	if current == nil {
		SendError(ctx, fasthttp.StatusNotFound, "Project not found")
		return
	}
	var request projectRequest
	if err := json.Unmarshal(ctx.PostBody(), &request); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid request payload")
		return
	}
	expiresAt := current.ExpiresAt
	if request.ExpiresAt != nil {
		expiresAt, err = parseProjectExpiry(request.ExpiresAt)
		if err != nil {
			SendError(ctx, fasthttp.StatusBadRequest, err.Error())
			return
		}
	}
	name, description, accessRule, membershipMode, accountingMode, splitPolicy := current.Name, current.Description, current.AccessRule, current.MembershipMode, current.AccountingMode, current.SplitPolicy
	if request.Name != "" {
		name = request.Name
	}
	if request.Description != "" {
		description = request.Description
	}
	if request.AccessRule != "" {
		accessRule = request.AccessRule
	}
	if request.MembershipMode != "" {
		membershipMode = request.MembershipMode
	}
	if request.AccountingMode != "" {
		accountingMode = request.AccountingMode
	}
	if request.SplitPolicy != "" {
		splitPolicy = request.SplitPolicy
	}
	enabled := current.Enabled
	if request.Enabled != nil {
		enabled = *request.Enabled
	}
	providers, models := current.AllowedProviders, current.AllowedModels
	allowAllProviders := current.AllowAllProviders
	if request.AllowAllProviders != nil {
		allowAllProviders = *request.AllowAllProviders
	}
	if request.AllowedProviders != nil {
		providers = request.AllowedProviders
	}
	if request.AllowedModels != nil {
		models = request.AllowedModels
	}
	audit, outbox := h.audit(ctx, current.ID, "governance.project.updated")
	updated, err := h.store.UpdateProjectAudited(ctx, current.ID, name, description, enabled, expiresAt, accessRule, membershipMode, accountingMode, splitPolicy, allowAllProviders, providers, models, audit, outbox)
	if h.writeError(ctx, err) {
		return
	}
	SendJSON(ctx, newProjectResponse(*updated))
}

func (h *ProjectsHandler) delete(ctx *fasthttp.RequestCtx) {
	if !allowSessionStateChange(ctx) {
		SendError(ctx, fasthttp.StatusForbidden, "Invalid request origin")
		return
	}
	id, _ := ctx.UserValue("id").(string)
	audit, outbox := h.audit(ctx, strings.TrimSpace(id), "governance.project.deleted")
	if h.writeError(ctx, h.store.DeleteProjectAudited(ctx, strings.TrimSpace(id), audit, outbox)) {
		return
	}
	ctx.SetStatusCode(fasthttp.StatusNoContent)
}

func (h *ProjectsHandler) listMembers(ctx *fasthttp.RequestCtx) {
	id, _ := ctx.UserValue("id").(string)
	members, err := h.store.ListProjectMembers(ctx, strings.TrimSpace(id))
	if h.writeError(ctx, err) {
		return
	}
	SendJSON(ctx, map[string]any{"members": members})
}

func (h *ProjectsHandler) replaceMembers(ctx *fasthttp.RequestCtx) {
	if !allowSessionStateChange(ctx) {
		SendError(ctx, fasthttp.StatusForbidden, "Invalid request origin")
		return
	}
	id, _ := ctx.UserValue("id").(string)
	request := struct {
		UserIDs []string `json:"user_ids"`
	}{}
	if err := json.Unmarshal(ctx.PostBody(), &request); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid request payload")
		return
	}
	audit, outbox := h.audit(ctx, strings.TrimSpace(id), "governance.project.members_updated")
	if h.writeError(ctx, h.store.ReplaceManualProjectMembersAudited(ctx, strings.TrimSpace(id), request.UserIDs, canonicalActorUserID(ctx), audit, outbox)) {
		return
	}
	h.listMembers(ctx)
}

func (h *ProjectsHandler) audit(ctx *fasthttp.RequestCtx, targetID, action string) (*tables.TableAuditEvent, *tables.TableOutboxEvent) {
	eventID := uuid.NewString()
	actor := "legacy:local_admin"
	if userID := canonicalActorUserID(ctx); userID != nil {
		actor = "user:" + *userID
	}
	return &tables.TableAuditEvent{ID: eventID, ActorPrincipal: actor, TargetType: "project", TargetID: &targetID, Action: action, OccurredAt: time.Now().UTC()}, &tables.TableOutboxEvent{Topic: "governance.project.changed", DeduplicationKey: "governance.project:" + eventID, Payload: map[string]any{"project_id": targetID, "action": action}}
}

func projectQueryParams(ctx *fasthttp.RequestCtx) (configstore.ProjectQueryParams, bool) {
	params := configstore.ProjectQueryParams{Search: string(ctx.QueryArgs().Peek("search")), Limit: 50}
	if raw := ctx.QueryArgs().Peek("limit"); len(raw) > 0 {
		value, err := fasthttp.ParseUint(raw)
		if err != nil || value == 0 || value > 100 {
			return configstore.ProjectQueryParams{}, false
		}
		params.Limit = int(value)
	}
	if raw := ctx.QueryArgs().Peek("offset"); len(raw) > 0 {
		value, err := fasthttp.ParseUint(raw)
		if err != nil {
			return configstore.ProjectQueryParams{}, false
		}
		params.Offset = int(value)
	}
	return params, true
}

func (h *ProjectsHandler) writeError(ctx *fasthttp.RequestCtx, err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, configstore.ErrNotFound):
		SendError(ctx, fasthttp.StatusNotFound, "Project or user not found")
	case errors.Is(err, configstore.ErrAlreadyExists):
		SendError(ctx, fasthttp.StatusConflict, "A project with that name already exists")
	case errors.Is(err, configstore.ErrProjectInUse):
		SendError(ctx, fasthttp.StatusConflict, "Project still has active members")
	default:
		logger.Error(fmt.Sprintf("project operation failed: %v", err))
		SendError(ctx, fasthttp.StatusInternalServerError, "Project operation failed")
	}
	return true
}
