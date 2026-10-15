package configstore

import (
	"context"
	"testing"

	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReplaceManualUserTeamMembershipsPreservesDirectoryAssignments(t *testing.T) {
	store := setupIdentityTestStore(t, ":memory:")
	ctx := context.Background()
	user := &tables.TableUser{Email: ptr("teams@example.test"), Status: tables.UserStatusActive}
	require.NoError(t, store.CreateUser(ctx, user))
	for _, team := range []tables.TableTeam{{ID: "team-a", Name: "Alpha"}, {ID: "team-b", Name: "Beta"}, {ID: "team-c", Name: "Gamma"}} {
		require.NoError(t, store.CreateTeam(ctx, &team))
	}
	provider := "entra"
	require.NoError(t, store.DB().Create(&tables.TableUserTeamMembership{
		ID: "directory-grant", UserID: user.ID, TeamID: "team-c", Source: tables.UserTeamSourceDirectorySync, ProviderID: &provider,
	}).Error)

	audit := &tables.TableAuditEvent{ActorPrincipal: "user:admin", TargetType: "user", TargetID: &user.ID, Action: "identity.user.teams_updated", ChangedFields: map[string]any{"team_ids": []string{"team-a", "team-b"}}}
	outbox := &tables.TableOutboxEvent{Topic: "identity.user.changed", DeduplicationKey: "identity.user:teams-test", Payload: map[string]any{"user_id": user.ID}}
	require.NoError(t, store.ReplaceManualUserTeamMembershipsAudited(ctx, user.ID, []string{"team-a", "team-b", "team-a"}, nil, audit, outbox))

	memberships, err := store.ListUserTeamMemberships(ctx, user.ID)
	require.NoError(t, err)
	require.Len(t, memberships, 3)
	assert.Equal(t, "team-a", memberships[0].TeamID)
	assert.Equal(t, tables.UserTeamSourceManual, memberships[0].Source)
	assert.Equal(t, "team-b", memberships[1].TeamID)
	assert.Equal(t, "team-c", memberships[2].TeamID)
	assert.Equal(t, tables.UserTeamSourceDirectorySync, memberships[2].Source)
}

func TestReplaceManualUserTeamMembershipsRejectsUnknownTeamWithoutMutation(t *testing.T) {
	store := setupIdentityTestStore(t, ":memory:")
	ctx := context.Background()
	user := &tables.TableUser{Email: ptr("teams-unknown@example.test"), Status: tables.UserStatusActive}
	require.NoError(t, store.CreateUser(ctx, user))
	require.NoError(t, store.CreateTeam(ctx, &tables.TableTeam{ID: "team-a", Name: "Alpha"}))

	err := store.ReplaceManualUserTeamMembershipsAudited(ctx, user.ID, []string{"missing"}, nil,
		&tables.TableAuditEvent{ActorPrincipal: "user:admin", TargetType: "user", TargetID: &user.ID, Action: "identity.user.teams_updated"},
		&tables.TableOutboxEvent{Topic: "identity.user.changed", DeduplicationKey: "identity.user:teams-unknown"},
	)
	require.ErrorIs(t, err, ErrNotFound)
	memberships, err := store.ListUserTeamMemberships(ctx, user.ID)
	require.NoError(t, err)
	assert.Empty(t, memberships)
}
