package configstore

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/stretchr/testify/require"
)

func TestNormalizeAccessProfileProviderConfigsRejectsDuplicateProviderRules(t *testing.T) {
	_, err := NormalizeAccessProfileProviderConfigs([]tables.AccessProfileProviderConfig{
		{ProviderName: " OpenAI "},
		{ProviderName: "openai"},
	})
	require.Error(t, err)
}

func TestAccessProfileProviderConfigRejectsUnsupportedBudgetFields(t *testing.T) {
	var config tables.AccessProfileProviderConfig
	err := json.Unmarshal([]byte(`{"provider_name":"openai","budgets":[{"budget_id":"monthly"}]}`), &config)
	require.Error(t, err, "unsupported policy fields must not be silently discarded")
}

func TestAccessProfileManagementNormalizesAssignmentsAndBlocksDelete(t *testing.T) {
	store := setupIdentityTestStore(t, ":memory:")
	ctx := context.Background()
	user := &tables.TableUser{ID: uuid.NewString(), Email: stringPointerForTest("profile-owner@example.com"), DisplayName: "Profile owner", Status: tables.UserStatusActive}
	require.NoError(t, store.CreateUser(ctx, user))

	audit, outbox := roleAuditFixtures()
	profile, err := store.CreateAccessProfileAudited(ctx, &tables.TableAccessProfile{
		ID: "developer", Name: "Developer", Description: "Developer access", AllowedProviders: []string{"openai", "openai"}, AllowedModels: []string{"gpt-4.1"}, Enabled: true,
		ProviderConfigs: []tables.AccessProfileProviderConfig{{ProviderName: " OpenAI ", AllowedModels: []string{"gpt-4.1"}, KeyIDs: []string{"key-a", "key-a"}}},
	}, audit, outbox)
	require.NoError(t, err)
	require.Equal(t, []string{"openai"}, profile.AllowedProviders)
	require.Len(t, profile.ProviderConfigs, 1)
	require.Equal(t, "openai", profile.ProviderConfigs[0].ProviderName)
	require.Equal(t, []string{"key-a"}, profile.ProviderConfigs[0].KeyIDs)

	audit, outbox = roleAuditFixtures()
	require.NoError(t, store.ReplaceManualUserAccessProfilesAudited(ctx, user.ID, []string{profile.ID, profile.ID}, nil, audit, outbox))
	assignments, err := store.ListUserAccessProfileAssignments(ctx, user.ID)
	require.NoError(t, err)
	require.Len(t, assignments, 1)
	require.Equal(t, tables.AccessProfileSourceManual, assignments[0].Source)

	audit, outbox = roleAuditFixtures()
	require.ErrorIs(t, store.DeleteAccessProfileAudited(ctx, profile.ID, audit, outbox), ErrAccessProfileInUse)

	audit, outbox = roleAuditFixtures()
	updated, err := store.UpdateAccessProfileAudited(ctx, profile.ID, "Developer Plus", "Expanded", false, true, []string{"anthropic"}, []string{"claude"}, []tables.AccessProfileProviderConfig{{ProviderName: "anthropic", AllModelsAllowed: true, KeyIDs: []string{"key-c"}}}, []string{"search"}, audit, outbox)
	require.NoError(t, err)
	require.Equal(t, "Developer Plus", updated.Name)
	require.False(t, updated.Enabled)
	require.True(t, updated.AllowAllProviders)
	require.Len(t, updated.ProviderConfigs, 1)
	require.Equal(t, "anthropic", updated.ProviderConfigs[0].ProviderName)
	require.Equal(t, []string{"key-c"}, updated.ProviderConfigs[0].KeyIDs)
	reloaded, err := store.GetAccessProfile(ctx, profile.ID)
	require.NoError(t, err)
	require.Len(t, reloaded.ProviderConfigs, 1)
	require.Equal(t, []string{"key-c"}, reloaded.ProviderConfigs[0].KeyIDs)
}

func TestRoleAccessProfileAssignmentsAreAuditedAndProtectRoleAndProfile(t *testing.T) {
	store := setupIdentityTestStore(t, ":memory:")
	ctx := context.Background()
	audit, outbox := roleAuditFixtures()
	role, err := store.CreateRoleAudited(ctx, &tables.TableRole{ID: "engineering", Name: "engineering", DisplayName: "Engineering"}, audit, outbox)
	require.NoError(t, err)

	audit, outbox = roleAuditFixtures()
	profile, err := store.CreateAccessProfileAudited(ctx, &tables.TableAccessProfile{ID: "engineering-profile", Name: "Engineering", Enabled: true}, audit, outbox)
	require.NoError(t, err)

	audit, outbox = roleAuditFixtures()
	require.NoError(t, store.ReplaceManualRoleAccessProfilesAudited(ctx, role.ID, []string{profile.ID, profile.ID}, nil, audit, outbox))
	assignments, err := store.ListRoleAccessProfileAssignments(ctx, role.ID)
	require.NoError(t, err)
	require.Len(t, assignments, 1)
	require.Equal(t, tables.RoleAccessProfileSourceManual, assignments[0].Source)

	audit, outbox = roleAuditFixtures()
	require.ErrorIs(t, store.DeleteRoleAudited(ctx, role.ID, audit, outbox), ErrRoleInUse)
	audit, outbox = roleAuditFixtures()
	require.ErrorIs(t, store.DeleteAccessProfileAudited(ctx, profile.ID, audit, outbox), ErrAccessProfileInUse)

	audit, outbox = roleAuditFixtures()
	require.NoError(t, store.ReplaceManualRoleAccessProfilesAudited(ctx, role.ID, nil, nil, audit, outbox))
	audit, outbox = roleAuditFixtures()
	require.NoError(t, store.DeleteAccessProfileAudited(ctx, profile.ID, audit, outbox))
	audit, outbox = roleAuditFixtures()
	require.NoError(t, store.DeleteRoleAudited(ctx, role.ID, audit, outbox))
}
