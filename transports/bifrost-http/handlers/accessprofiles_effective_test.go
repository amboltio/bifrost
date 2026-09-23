package handlers

import (
	"encoding/json"
	"net/url"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/configstore"
	"github.com/maximhq/bifrost/framework/grant"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

type effectiveAccessStoreStub struct {
	configstore.ConfigStore
	configstore.AccessProfileManagementStore
}

type effectiveAccessResolverStub struct {
	access              schemas.Access
	calls               int
	userID              string
	provider            string
	projectID           string
	limitsWereUnsettled bool
}

func (s *effectiveAccessResolverStub) ResolveAccess(ctx *schemas.BifrostContext) (schemas.Access, error) {
	s.calls++
	if identity := ctx.Grant().Identity(); identity != nil && identity.User() != nil {
		s.userID = identity.User().ID
	}
	s.provider, _ = ctx.Value(schemas.BifrostContextKeyGovernanceRequestProvider).(string)
	if headers, ok := ctx.Value(schemas.BifrostContextKeyRequestHeaders).(map[string]string); ok {
		s.projectID = headers[schemas.HeaderGovernanceProjectID]
	}
	s.limitsWereUnsettled = ctx.Grant().Limits() == nil
	return s.access, nil
}

func TestEffectiveAccessUsesResolverForSelectionAndDoesNotSettleLimits(t *testing.T) {
	profile := grant.NewPermit(grant.PermitAccessProfile, "profile-1", "Engineering", true, false,
		[]schemas.ProviderPermit{{Provider: "openai", AllowedModels: schemas.WhiteList{"gpt-4o"}, KeyIDs: schemas.WhiteList{"*"}}}, nil)
	project := grant.NewPermit(grant.PermitProject, "project-1", "Project One", true, false,
		[]schemas.ProviderPermit{{Provider: "openai", AllowedModels: schemas.WhiteList{"gpt-4o"}, KeyIDs: schemas.WhiteList{"*"}}}, nil)
	access := grant.NewAccess([]schemas.Permit{profile}, project, grant.Intersect, nil)
	resolver := &effectiveAccessResolverStub{access: access}
	handler := NewAccessProfilesHandler(effectiveAccessStoreStub{}, resolver)
	ctx := effectiveAccessRequest("user-1", "user-1", "provider=openai&model=gpt-4o&project_id=project-1")

	handler.effectiveAccess(ctx)

	require.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	require.Equal(t, 1, resolver.calls)
	require.Equal(t, "user-1", resolver.userID)
	require.Equal(t, "openai", resolver.provider)
	require.Equal(t, "project-1", resolver.projectID)
	require.True(t, resolver.limitsWereUnsettled, "dry run must not settle accounting limits")
	var response struct {
		Allowed              bool     `json:"allowed"`
		Provider             string   `json:"provider"`
		Model                string   `json:"model"`
		ProjectID            string   `json:"project_id"`
		ContributingProfiles []string `json:"contributing_profile_ids"`
	}
	require.NoError(t, json.Unmarshal(ctx.Response.Body(), &response))
	require.True(t, response.Allowed)
	require.Equal(t, "openai", response.Provider)
	require.Equal(t, "gpt-4o", response.Model)
	require.Equal(t, "project-1", response.ProjectID)
	require.Equal(t, []string{"profile-1"}, response.ContributingProfiles)
}

func TestEffectiveAccessReportsSameModelDecisionAsInferenceResolver(t *testing.T) {
	profile := grant.NewPermit(grant.PermitAccessProfile, "profile-1", "Engineering", true, false,
		[]schemas.ProviderPermit{{Provider: "openai", AllowedModels: schemas.WhiteList{"gpt-4o"}, KeyIDs: schemas.WhiteList{"*"}}}, nil)
	access := grant.NewAccess([]schemas.Permit{profile}, nil, "", nil)
	resolver := &effectiveAccessResolverStub{access: access}
	handler := NewAccessProfilesHandler(effectiveAccessStoreStub{}, resolver)
	ctx := effectiveAccessRequest("user-1", "user-1", "provider=openai&model=o3")

	handler.effectiveAccess(ctx)

	var response struct {
		Allowed bool `json:"allowed"`
	}
	require.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	require.NoError(t, json.Unmarshal(ctx.Response.Body(), &response))
	require.Equal(t, access.IsModelAllowed("openai", "o3"), response.Allowed)
	require.False(t, response.Allowed)
}

func TestEffectiveAccessForbidsAnotherUsersDataWithoutAdminAuthority(t *testing.T) {
	resolver := &effectiveAccessResolverStub{access: grant.NewAccess(nil, nil, "", nil)}
	handler := NewAccessProfilesHandler(effectiveAccessStoreStub{}, resolver)
	ctx := effectiveAccessRequest("actor-1", "target-2", "")

	handler.effectiveAccess(ctx)

	require.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
	require.Zero(t, resolver.calls, "unauthorized previews must not invoke the resolver")
}

func TestEffectiveAccessRejectsModelWithoutProvider(t *testing.T) {
	resolver := &effectiveAccessResolverStub{access: grant.NewAccess(nil, nil, "", nil)}
	handler := NewAccessProfilesHandler(effectiveAccessStoreStub{}, resolver)
	ctx := effectiveAccessRequest("user-1", "user-1", "model=gpt-4o")

	handler.effectiveAccess(ctx)

	require.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
	require.Zero(t, resolver.calls)
}

func TestEffectiveAccessDoesNotFallBackWhenSelectedProjectFailsToResolve(t *testing.T) {
	profile := grant.NewPermit(grant.PermitAccessProfile, "profile-1", "Engineering", true, false,
		[]schemas.ProviderPermit{{Provider: "openai", AllowedModels: schemas.WhiteList{"*"}, KeyIDs: schemas.WhiteList{"*"}}}, nil)
	resolver := &effectiveAccessResolverStub{access: grant.NewAccess([]schemas.Permit{profile}, nil, "", nil)}
	handler := NewAccessProfilesHandler(effectiveAccessStoreStub{}, resolver)
	ctx := effectiveAccessRequest("user-1", "user-1", "provider=openai&project_id=missing-project")

	handler.effectiveAccess(ctx)

	var response struct {
		Allowed         bool `json:"allowed"`
		ProjectResolved bool `json:"project_resolved"`
	}
	require.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	require.NoError(t, json.Unmarshal(ctx.Response.Body(), &response))
	require.False(t, response.Allowed, "an unresolved requested project must not fall back to user-only access")
	require.False(t, response.ProjectResolved)
}

func effectiveAccessRequest(actorID, targetID, rawQuery string) *fasthttp.RequestCtx {
	ctx := &fasthttp.RequestCtx{}
	requestURI := "/api/governance/users/" + url.PathEscape(targetID) + "/effective-access"
	if rawQuery != "" {
		requestURI += "?" + rawQuery
	}
	var request fasthttp.Request
	request.SetRequestURI(requestURI)
	ctx.Init(&request, nil, nil)
	ctx.SetUserValue("id", targetID)
	if actorID != "" {
		ctx.SetUserValue(schemas.BifrostContextKeyUserID, actorID)
	}
	return ctx
}
