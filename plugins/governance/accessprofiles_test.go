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
	assignments []configstoreTables.TableUserAccessProfileAssignment
	profiles    map[string]*configstoreTables.TableAccessProfile
	err         error
	userIDs     []string
}

func (s *fakeAccessProfileStore) ListUserAccessProfileAssignments(_ context.Context, userID string) ([]configstoreTables.TableUserAccessProfileAssignment, error) {
	s.userIDs = append(s.userIDs, userID)
	if s.err != nil {
		return nil, s.err
	}
	return s.assignments, nil
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
