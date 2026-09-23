package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/fasthttp/router"
	"github.com/google/uuid"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/authorization"
	"github.com/maximhq/bifrost/framework/configstore"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/maximhq/bifrost/framework/grant"
	"github.com/maximhq/bifrost/transports/bifrost-http/lib"
	"github.com/valyala/fasthttp"
)

// AccessProfilesHandler exposes the reusable policy and user-assignment
// surface. The handler deliberately returns only allow-list metadata; secrets
// and provider credentials never belong in an access profile.
type AccessProfilesHandler struct {
	store        configstore.AccessProfileManagementStore
	resolver     EffectiveAccessResolver
	roleResolver UserRoleResolver
}

// EffectiveAccessResolver is the same permit resolver used by inference. The preview only resolves
// access; admission and limit settlement remain inference responsibilities.
type EffectiveAccessResolver interface {
	ResolveAccess(ctx *schemas.BifrostContext) (schemas.Access, error)
}

func NewAccessProfilesHandler(store configstore.ConfigStore, resolvers ...EffectiveAccessResolver) *AccessProfilesHandler {
	management, ok := store.(configstore.AccessProfileManagementStore)
	if !ok {
		return nil
	}
	var resolver EffectiveAccessResolver
	if len(resolvers) > 0 {
		resolver = resolvers[0]
	}
	var roleResolver UserRoleResolver
	if candidate, ok := store.(UserRoleResolver); ok {
		roleResolver = candidate
	}
	return &AccessProfilesHandler{store: management, resolver: resolver, roleResolver: roleResolver}
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
	r.GET("/api/governance/roles/{id}/access-profiles", lib.ChainMiddlewares(h.listRoleAssignments, middlewares...))
	r.PUT("/api/governance/roles/{id}/access-profiles", lib.ChainMiddlewares(h.replaceRoleAssignments, middlewares...))
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
	AllowAllProviders *bool    `json:"allow_all_providers"`
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
	allowAllProviders := false
	if request.AllowAllProviders != nil {
		allowAllProviders = *request.AllowAllProviders
	}
	profile := &tables.TableAccessProfile{ID: strings.TrimSpace(request.ID), Name: strings.TrimSpace(request.Name), Description: strings.TrimSpace(request.Description), Enabled: enabled, AllowAllProviders: allowAllProviders, AllowedProviders: request.AllowedProviders, AllowedModels: request.AllowedModels, AllowedMCPTools: request.AllowedMCPTools, CreatedByUserID: canonicalActorUserID(ctx)}
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
	if request.AllowedMCPTools != nil {
		mcpTools = request.AllowedMCPTools
	}
	audit, outbox := h.audit(ctx, current.ID, "governance.access_profile.updated")
	updated, err := h.store.UpdateAccessProfileAudited(ctx, current.ID, name, description, enabled, allowAllProviders, providers, models, mcpTools, audit, outbox)
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

func (h *AccessProfilesHandler) listRoleAssignments(ctx *fasthttp.RequestCtx) {
	roleID, _ := ctx.UserValue("id").(string)
	roleID = strings.TrimSpace(roleID)
	assignments, err := h.store.ListRoleAccessProfileAssignments(ctx, roleID)
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

func (h *AccessProfilesHandler) replaceRoleAssignments(ctx *fasthttp.RequestCtx) {
	if !allowSessionStateChange(ctx) {
		SendError(ctx, fasthttp.StatusForbidden, "Invalid request origin")
		return
	}
	roleID, _ := ctx.UserValue("id").(string)
	request := struct {
		AccessProfileIDs []string `json:"access_profile_ids"`
	}{}
	if err := json.Unmarshal(ctx.PostBody(), &request); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid request payload")
		return
	}
	audit, outbox := h.roleAssignmentAudit(ctx, strings.TrimSpace(roleID))
	if h.writeError(ctx, h.store.ReplaceManualRoleAccessProfilesAudited(ctx, strings.TrimSpace(roleID), request.AccessProfileIDs, canonicalActorUserID(ctx), audit, outbox)) {
		return
	}
	h.listRoleAssignments(ctx)
}

func (h *AccessProfilesHandler) effectiveAccess(ctx *fasthttp.RequestCtx) {
	userID, _ := ctx.UserValue("id").(string)
	userID = strings.TrimSpace(userID)
	if userID == "" || len(userID) > 256 {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid user ID")
		return
	}
	actorID, _ := ctx.UserValue(schemas.BifrostContextKeyUserID).(string)
	if strings.TrimSpace(actorID) != userID && !authBypassed(ctx) && !isTrustedLocalAdmin(ctx) && !h.canReadOtherUserEffectiveAccess(actorID) {
		SendError(ctx, fasthttp.StatusForbidden, "Forbidden")
		return
	}
	if h.resolver == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "Effective access preview is unavailable")
		return
	}
	selection, ok := effectiveAccessSelectionFromRequest(ctx)
	if !ok {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid access selection")
		return
	}

	// Build the subject context from the authorized target, not from a request-supplied user header.
	// It intentionally carries no virtual-key credential: this endpoint previews that user's
	// profile grants without pretending a shared key identifies them.
	bifrostCtx := schemas.NewBifrostContext(ctx, schemas.NoDeadline)
	requestGrant := grant.New()
	requestGrant.SetIdentity(grant.NewIdentity(schemas.Credential{}, &schemas.UserRef{ID: userID}, nil, nil, nil, nil, nil))
	if !bifrostCtx.SetGrant(requestGrant) {
		SendError(ctx, fasthttp.StatusInternalServerError, "Effective access preview failed")
		return
	}
	if selection.provider != "" {
		bifrostCtx.SetValue(schemas.BifrostContextKeyGovernanceRequestProvider, selection.provider)
	}
	if selection.projectID != "" {
		bifrostCtx.SetValue(schemas.BifrostContextKeyRequestHeaders, map[string]string{
			schemas.HeaderGovernanceProjectID: selection.projectID,
		})
	}
	access, err := h.resolver.ResolveAccess(bifrostCtx)
	if err != nil {
		logger.Error(fmt.Sprintf("effective access preview failed: %v", err))
		SendError(ctx, fasthttp.StatusInternalServerError, "Effective access preview failed")
		return
	}
	projectResolved := selection.projectID == ""
	if selection.projectID != "" && access != nil && access.Scoping() != nil {
		projectResolved = access.Scoping().Type() == string(grant.PermitProject) && access.Scoping().ID() == selection.projectID
	}
	SendJSON(ctx, explainEffectiveAccess(userID, selection, access, projectResolved))
}

func (h *AccessProfilesHandler) canReadOtherUserEffectiveAccess(actorID string) bool {
	if h.roleResolver == nil || strings.TrimSpace(actorID) == "" {
		return false
	}
	roles, err := h.roleResolver.GetRolesByUserID(context.Background(), strings.TrimSpace(actorID))
	if err != nil {
		return false
	}
	usersRead, profilesRead := false, false
	for _, role := range roles {
		if role.ID == tables.RoleIDSuperAdmin {
			return true
		}
		usersRead = usersRead || authorization.Has(role.Permissions, authorization.PermissionUsersRead)
		profilesRead = profilesRead || authorization.Has(role.Permissions, authorization.PermissionAccessProfilesRead)
	}
	return usersRead && profilesRead
}

type effectiveAccessSelection struct {
	provider  string
	model     string
	projectID string
}

func effectiveAccessSelectionFromRequest(ctx *fasthttp.RequestCtx) (effectiveAccessSelection, bool) {
	args := ctx.QueryArgs()
	selection := effectiveAccessSelection{
		provider:  strings.ToLower(strings.TrimSpace(string(args.Peek("provider")))),
		model:     strings.TrimSpace(string(args.Peek("model"))),
		projectID: strings.TrimSpace(string(args.Peek("project_id"))),
	}
	if len(selection.provider) > 128 || len(selection.model) > 256 || len(selection.projectID) > 256 {
		return effectiveAccessSelection{}, false
	}
	if selection.model != "" && selection.provider == "" {
		return effectiveAccessSelection{}, false
	}
	return selection, true
}

type effectiveAccessSource struct {
	ID string `json:"id"`
}

type effectiveAccessExplanation struct {
	UserID                 string                  `json:"user_id"`
	Provider               string                  `json:"provider,omitempty"`
	Model                  string                  `json:"model,omitempty"`
	ProjectID              string                  `json:"project_id,omitempty"`
	ProjectResolved        *bool                   `json:"project_resolved,omitempty"`
	Allowed                *bool                   `json:"allowed,omitempty"`
	AllowAllProviders      bool                    `json:"allow_all_providers"`
	AllowAllMCPTools       bool                    `json:"allow_all_mcp_tools"`
	AllowedProviders       []string                `json:"allowed_providers"`
	AllowedMCPTools        []string                `json:"allowed_mcp_tools"`
	ContributingProfileIDs []string                `json:"contributing_profile_ids"`
	DeniedProfiles         []effectiveAccessSource `json:"denied_profiles"`
}

func explainEffectiveAccess(userID string, selection effectiveAccessSelection, access schemas.Access, projectResolved bool) effectiveAccessExplanation {
	response := effectiveAccessExplanation{
		UserID: userID, Provider: selection.provider, Model: selection.model, ProjectID: selection.projectID,
		AllowedProviders: []string{}, AllowedMCPTools: []string{}, ContributingProfileIDs: []string{}, DeniedProfiles: []effectiveAccessSource{},
	}
	if selection.projectID != "" {
		response.ProjectResolved = &projectResolved
	}
	if !projectResolved {
		if selection.provider != "" {
			allowed := false
			response.Allowed = &allowed
		}
		return response
	}
	if access == nil {
		response.AllowAllProviders = true
		response.AllowAllMCPTools = true
		if selection.provider != "" {
			allowed := true
			response.Allowed = &allowed
		}
		return response
	}

	providers := map[string]struct{}{}
	for _, permit := range allEffectiveAccessPermits(access) {
		if permit == nil {
			continue
		}
		for _, providerPermit := range permit.ProviderPermits() {
			provider := strings.TrimSpace(providerPermit.Provider)
			if provider != "" && access.IsProviderAllowed(provider) {
				if selection.model == "" || access.IsModelAllowed(provider, selection.model) {
					providers[provider] = struct{}{}
				}
			}
		}
	}
	response.AllowedProviders = boundedSortedSet(providers, 100)
	response.AllowAllProviders = effectiveAccessAllowsAllProviders(access)
	response.AllowedMCPTools = boundedSortedSet(sliceSet(access.MCPToolIncludeList()), 100)

	if selection.provider == "" {
		response.ContributingProfileIDs = profilePermitIDs(allEffectiveAccessPermits(access), 50)
		return response
	}
	allowed := access.IsProviderAllowed(selection.provider)
	if selection.model != "" {
		allowed = access.IsModelAllowed(selection.provider, selection.model)
	}
	response.Allowed = &allowed
	if allowed {
		response.ContributingProfileIDs = profilePermitIDs(access.PermitsForModel(selection.provider, selection.model), 50)
	} else {
		response.DeniedProfiles = profilePermitSources(access.DeniedPermitsForModel(selection.provider, selection.model), 50)
	}
	return response
}

func allEffectiveAccessPermits(access schemas.Access) []schemas.Permit {
	if access == nil {
		return nil
	}
	permits := append([]schemas.Permit(nil), access.Bases()...)
	if access.Scoping() != nil {
		permits = append(permits, access.Scoping())
	}
	return permits
}

func effectiveAccessAllowsAllProviders(access schemas.Access) bool {
	baseAllowsAll := false
	for _, permit := range access.Bases() {
		if permit != nil && permit.AllowsAllProviders() {
			baseAllowsAll = true
			break
		}
	}
	scope := access.Scoping()
	if scope == nil {
		return baseAllowsAll
	}
	scopeAllowsAll := scope.AllowsAllProviders()
	switch access.Mode() {
	case string(grant.Union):
		return baseAllowsAll || scopeAllowsAll
	case string(grant.Intersect):
		return baseAllowsAll && scopeAllowsAll
	default:
		return false
	}
}

func profilePermitIDs(permits []schemas.Permit, limit int) []string {
	set := map[string]struct{}{}
	for _, permit := range permits {
		if permit != nil && permit.Type() == string(grant.PermitAccessProfile) && permit.ID() != "" {
			set[permit.ID()] = struct{}{}
		}
	}
	return boundedSortedSet(set, limit)
}

func profilePermitSources(permits []schemas.Permit, limit int) []effectiveAccessSource {
	sources := make([]effectiveAccessSource, 0, min(limit, len(permits)))
	seen := map[string]struct{}{}
	for _, permit := range permits {
		if permit == nil || permit.Type() != string(grant.PermitAccessProfile) || permit.ID() == "" {
			continue
		}
		if _, exists := seen[permit.ID()]; exists {
			continue
		}
		seen[permit.ID()] = struct{}{}
		sources = append(sources, effectiveAccessSource{ID: permit.ID()})
		if len(sources) == limit {
			break
		}
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].ID < sources[j].ID })
	return sources
}

func sliceSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "" {
			set[value] = struct{}{}
		}
	}
	return set
}

func boundedSortedSet(values map[string]struct{}, limit int) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	if len(result) > limit {
		result = result[:limit]
	}
	return result
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

func (h *AccessProfilesHandler) roleAssignmentAudit(ctx *fasthttp.RequestCtx, roleID string) (*tables.TableAuditEvent, *tables.TableOutboxEvent) {
	eventID := uuid.NewString()
	actor := "legacy:local_admin"
	if userID := canonicalActorUserID(ctx); userID != nil {
		actor = "user:" + *userID
	}
	return &tables.TableAuditEvent{ID: eventID, ActorPrincipal: actor, TargetType: "role", TargetID: &roleID, Action: "governance.role.access_profiles_updated", OccurredAt: time.Now().UTC()}, &tables.TableOutboxEvent{Topic: "governance.role.access_profile.changed", DeduplicationKey: "governance.role.access_profile:" + eventID, Payload: map[string]any{"role_id": roleID, "action": "access_profiles_updated"}}
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
