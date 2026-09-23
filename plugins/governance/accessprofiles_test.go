package governance

import (
	"context"
	"errors"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/configstore"
	configstoreTables "github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/maximhq/bifrost/framework/grant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeAccessProfileStore struct {
	configstore.AccessProfileManagementStore
	assignments     []configstoreTables.TableUserAccessProfileAssignment
	roleAssignments []configstoreTables.TableRoleAccessProfileAssignment
	profiles        map[string]*configstoreTables.TableAccessProfile
	err             error
	userIDs         []string
}

type fakeUserRoleStore struct {
	configstore.ConfigStore
	roles []configstoreTables.TableRole
	err   error
}

func (s fakeUserRoleStore) GetRolesByUserID(context.Context, string) ([]configstoreTables.TableRole, error) {
	return s.roles, s.err
}

func (s *fakeAccessProfileStore) ListUserAccessProfileAssignments(_ context.Context, userID string) ([]configstoreTables.TableUserAccessProfileAssignment, error) {
	s.userIDs = append(s.userIDs, userID)
	if s.err != nil {
		return nil, s.err
	}
	return s.assignments, nil
}

func (s *fakeAccessProfileStore) ListRoleAccessProfileAssignments(_ context.Context, roleID string) ([]configstoreTables.TableRoleAccessProfileAssignment, error) {
	if s.err != nil {
		return nil, s.err
	}
	result := make([]configstoreTables.TableRoleAccessProfileAssignment, 0)
	for _, assignment := range s.roleAssignments {
		if assignment.RoleID == roleID {
			result = append(result, assignment)
		}
	}
	return result, nil
}

func (s *fakeAccessProfileStore) GetAccessProfile(_ context.Context, id string) (*configstoreTables.TableAccessProfile, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.profiles[id], nil
}

func TestResolvePermitsIncludesAssignedUserAccessProfiles(t *testing.T) {
	store := &fakeAccessProfileStore{
		assignments: []configstoreTables.TableUserAccessProfileAssignment{
			{ID: "a1", UserID: "user-1", AccessProfileID: "engineering", Source: configstoreTables.AccessProfileSourceManual},
			{ID: "a2", UserID: "user-1", AccessProfileID: "engineering", Source: configstoreTables.AccessProfileSourceOIDCClaim},
			{ID: "a3", UserID: "user-1", AccessProfileID: "research", Source: configstoreTables.AccessProfileSourceManual},
			{ID: "a4", UserID: "user-1", AccessProfileID: "disabled", Source: configstoreTables.AccessProfileSourceManual},
		},
		profiles: map[string]*configstoreTables.TableAccessProfile{
			"engineering": {ID: "engineering", Name: "Engineering", Enabled: true, AllowedProviders: []string{"openai"}, AllowedModels: []string{"gpt-4o"}, AllowedMCPTools: []string{"sentry-find_issues"}},
			"research":    {ID: "research", Name: "Research", Enabled: true, AllowedProviders: []string{"anthropic"}},
			"disabled":    {ID: "disabled", Name: "Disabled", Enabled: false, AllowedProviders: []string{"bedrock"}},
		},
	}
	governanceStore := &LocalGovernanceStore{
		profileStore:  store,
		inMemoryStore: &mockInMemoryStore{clientNames: map[string]string{"sentry-id": "sentry"}},
	}
	ctx := presentUserCtx("user-1")

	bases, scoped, mode := governanceStore.ResolvePermits(ctx)

	assert.Nil(t, scoped)
	assert.Empty(t, mode)
	require.Len(t, bases, 2, "the same profile reached from two assignment sources is one permit")
	permits := make(map[string]schemas.Permit, len(bases))
	for _, permit := range bases {
		permits[permit.ID()] = permit
		assert.Equal(t, string(grant.PermitAccessProfile), permit.Type())
	}
	assert.Contains(t, permits, "engineering")
	assert.Contains(t, permits, "research")
	assert.NotContains(t, permits, "disabled", "inactive profile must not grant access")
	access := grant.NewAccess(bases, nil, "", nil)
	assert.True(t, access.IsModelAllowed("openai", "gpt-4o"))
	assert.True(t, access.IsModelAllowed("anthropic", "claude-sonnet"), "empty model list means every model for a listed provider")
	assert.False(t, access.IsProviderAllowed("bedrock"))
	assert.True(t, access.IsMCPToolAllowed("sentry-find_issues"))
	assert.Equal(t, []string{"user-1"}, store.userIDs)
}

func TestResolvePermitsIncludesRoleDefaultProfilesAndDeduplicatesSources(t *testing.T) {
	profileStore := &fakeAccessProfileStore{
		assignments: []configstoreTables.TableUserAccessProfileAssignment{{UserID: "user-1", AccessProfileID: "shared-profile"}},
		roleAssignments: []configstoreTables.TableRoleAccessProfileAssignment{
			{RoleID: "engineering", AccessProfileID: "shared-profile"},
			{RoleID: "engineering", AccessProfileID: "role-profile"},
		},
		profiles: map[string]*configstoreTables.TableAccessProfile{
			"shared-profile": {ID: "shared-profile", Name: "Shared", Enabled: true, AllowedProviders: []string{"openai"}},
			"role-profile":   {ID: "role-profile", Name: "Engineering default", Enabled: true, AllowedProviders: []string{"anthropic"}},
		},
	}
	roleStore := fakeUserRoleStore{roles: []configstoreTables.TableRole{{ID: "engineering"}}}
	governanceStore := &LocalGovernanceStore{profileStore: profileStore, configStore: roleStore}

	bases, _, _ := governanceStore.ResolvePermits(presentUserCtx("user-1"))

	require.Len(t, bases, 2, "direct and role-default paths to the same profile produce one grant")
	access := grant.NewAccess(bases, nil, "", nil)
	assert.True(t, access.IsProviderAllowed("openai"))
	assert.True(t, access.IsProviderAllowed("anthropic"))
}

func TestAccessProfileProviderConfigsRestrictModelsAndKeys(t *testing.T) {
	profile := &configstoreTables.TableAccessProfile{
		ID:               "engineering",
		Name:             "Engineering",
		Enabled:          true,
		AllowedProviders: []string{"openai", "anthropic"},
		ProviderConfigs: []configstoreTables.AccessProfileProviderConfig{
			{ProviderName: "openai", AllowedModels: []string{"gpt-4o"}, BlacklistedModels: []string{"gpt-4o-mini"}, KeyIDs: []string{"key-openai"}},
			{ProviderName: "anthropic", AllModelsAllowed: true},
		},
	}
	access := grant.NewAccess([]schemas.Permit{accessProfilePermit(profile, nil)}, nil, "", nil)

	assert.True(t, access.IsModelAllowed("openai", "gpt-4o"))
	assert.False(t, access.IsModelAllowed("openai", "gpt-4.1"), "provider config model lists are restrictive")
	assert.False(t, access.IsModelAllowed("openai", "gpt-4o-mini"), "blacklists take precedence over the allowlist")
	keyIDs, restricted := access.KeysForModel("openai", "gpt-4o")
	assert.True(t, restricted)
	assert.Equal(t, []string{"key-openai"}, keyIDs)
	keyIDs, restricted = access.KeysForModel("anthropic", "claude-sonnet")
	assert.True(t, restricted, "an empty provider key allowlist denies every key")
	assert.Empty(t, keyIDs)
	assert.False(t, access.IsModelAllowed("bedrock", "claude-sonnet"))
}

func TestResolvePermitsDoesNotInferProfileUserFromVirtualKey(t *testing.T) {
	profileStore := &fakeAccessProfileStore{
		assignments: []configstoreTables.TableUserAccessProfileAssignment{{ID: "a1", UserID: "user-1", AccessProfileID: "engineering"}},
		profiles:    map[string]*configstoreTables.TableAccessProfile{"engineering": {ID: "engineering", Name: "Engineering", Enabled: true, AllowedProviders: []string{"openai"}}},
	}
	governanceStore := &LocalGovernanceStore{profileStore: profileStore}
	governanceStore.storeVirtualKey("sk-bf-shared", buildVirtualKey("vk-shared", "sk-bf-shared", "Shared", true))
	ctx := presentCtx("sk-bf-shared")

	bases, _, _ := governanceStore.ResolvePermits(ctx)

	require.Len(t, bases, 1)
	assert.Equal(t, string(grant.PermitVirtualKey), bases[0].Type())
	assert.Empty(t, profileStore.userIDs, "a shared key does not establish which user's profile applies")
}

func TestResolvePermitsSkipsUnrepresentableAccessProfileAndStoreFailures(t *testing.T) {
	testCases := []struct {
		name  string
		store *fakeAccessProfileStore
	}{
		{
			name: "all-provider allowlist cannot be represented safely",
			store: &fakeAccessProfileStore{
				assignments: []configstoreTables.TableUserAccessProfileAssignment{{AccessProfileID: "broad"}},
				profiles: map[string]*configstoreTables.TableAccessProfile{
					"broad": {ID: "broad", Name: "Broad", Enabled: true, AllowAllProviders: true, AllowedModels: []string{"gpt-4o"}},
				},
			},
		},
		{
			name:  "profile store error",
			store: &fakeAccessProfileStore{err: errors.New("database unavailable")},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			governanceStore := &LocalGovernanceStore{profileStore: tc.store}
			ctx := presentUserCtx("user-1")

			bases, scoped, mode := governanceStore.ResolvePermits(ctx)

			assert.Empty(t, bases)
			assert.Nil(t, scoped)
			assert.Empty(t, mode)
		})
	}
}
