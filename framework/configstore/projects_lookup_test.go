package configstore

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/stretchr/testify/require"
)

func TestGetProjectByNameRequiresExactName(t *testing.T) {
	store := setupIdentityTestStore(t, ":memory:")
	ctx := context.Background()

	audit, outbox := roleAuditFixtures()
	projectID := uuid.NewString()
	_, err := store.CreateProjectAudited(ctx, &tables.TableProject{ID: projectID, Name: "Atlas", Description: "Atlas rollout"}, audit, outbox)
	require.NoError(t, err)

	got, err := store.GetProjectByName(ctx, "Atlas")
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, projectID, got.ID)

	got, err = store.GetProjectByName(ctx, "Atlas rollout")
	require.NoError(t, err)
	require.Nil(t, got, "a substring or description match must not select a project")
}

func TestHasProjectMemberMatchesExactProjectAndUser(t *testing.T) {
	store := setupIdentityTestStore(t, ":memory:")
	ctx := context.Background()
	user := &tables.TableUser{ID: uuid.NewString(), Email: stringPointerForTest("member@example.com"), DisplayName: "Member", Status: tables.UserStatusActive}
	require.NoError(t, store.CreateUser(ctx, user))
	audit, outbox := roleAuditFixtures()
	project, err := store.CreateProjectAudited(ctx, &tables.TableProject{Name: "Atlas"}, audit, outbox)
	require.NoError(t, err)
	audit, outbox = roleAuditFixtures()
	require.NoError(t, store.ReplaceManualProjectMembersAudited(ctx, project.ID, []string{user.ID}, nil, audit, outbox))

	member, err := store.HasProjectMember(ctx, project.ID, user.ID)
	require.NoError(t, err)
	require.True(t, member)

	member, err = store.HasProjectMember(ctx, project.ID, "another-user")
	require.NoError(t, err)
	require.False(t, member)
}
