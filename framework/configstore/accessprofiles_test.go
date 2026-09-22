package configstore

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/stretchr/testify/require"
)

func TestAccessProfileManagementNormalizesAssignmentsAndBlocksDelete(t *testing.T) {
	store := setupIdentityTestStore(t, ":memory:")
	ctx := context.Background()
	user := &tables.TableUser{ID: uuid.NewString(), Email: stringPointerForTest("profile-owner@example.com"), DisplayName: "Profile owner", Status: tables.UserStatusActive}
	require.NoError(t, store.CreateUser(ctx, user))

	audit, outbox := roleAuditFixtures()
	profile, err := store.CreateAccessProfileAudited(ctx, &tables.TableAccessProfile{
		ID: "developer", Name: "Developer", Description: "Developer access", AllowedProviders: []string{"openai", "openai"}, AllowedModels: []string{"gpt-4.1"}, Enabled: true,
	}, audit, outbox)
	require.NoError(t, err)
	require.Equal(t, []string{"openai"}, profile.AllowedProviders)

	audit, outbox = roleAuditFixtures()
	require.NoError(t, store.ReplaceManualUserAccessProfilesAudited(ctx, user.ID, []string{profile.ID, profile.ID}, nil, audit, outbox))
	assignments, err := store.ListUserAccessProfileAssignments(ctx, user.ID)
	require.NoError(t, err)
	require.Len(t, assignments, 1)
	require.Equal(t, tables.AccessProfileSourceManual, assignments[0].Source)

	audit, outbox = roleAuditFixtures()
	require.ErrorIs(t, store.DeleteAccessProfileAudited(ctx, profile.ID, audit, outbox), ErrAccessProfileInUse)

	audit, outbox = roleAuditFixtures()
	updated, err := store.UpdateAccessProfileAudited(ctx, profile.ID, "Developer Plus", "Expanded", false, true, []string{"anthropic"}, []string{"claude"}, []string{"search"}, audit, outbox)
	require.NoError(t, err)
	require.Equal(t, "Developer Plus", updated.Name)
	require.False(t, updated.Enabled)
	require.True(t, updated.AllowAllProviders)
}
