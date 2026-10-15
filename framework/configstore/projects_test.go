package configstore

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/stretchr/testify/require"
)

func TestProjectManagementValidatesPolicyAndPreservesMembers(t *testing.T) {
	store := setupIdentityTestStore(t, ":memory:")
	ctx := context.Background()
	user := &tables.TableUser{ID: uuid.NewString(), Email: stringPointerForTest("project-owner@example.com"), DisplayName: "Project owner", Status: tables.UserStatusActive}
	require.NoError(t, store.CreateUser(ctx, user))

	audit, outbox := roleAuditFixtures()
	project, err := store.CreateProjectAudited(ctx, &tables.TableProject{Name: "Evaluation", AccessRule: tables.ProjectAccessRuleIntersect, MembershipMode: tables.ProjectMembershipExplicit, AllowedProviders: []string{"openai", "openai"}}, audit, outbox)
	require.NoError(t, err)
	require.Equal(t, []string{"openai"}, project.AllowedProviders)

	audit, outbox = roleAuditFixtures()
	require.NoError(t, store.ReplaceManualProjectMembersAudited(ctx, project.ID, []string{user.ID, user.ID}, nil, audit, outbox))
	members, err := store.ListProjectMembers(ctx, project.ID)
	require.NoError(t, err)
	require.Len(t, members, 1)

	audit, outbox = roleAuditFixtures()
	require.ErrorIs(t, store.DeleteProjectAudited(ctx, project.ID, audit, outbox), ErrProjectInUse)

	audit, outbox = roleAuditFixtures()
	_, err = store.CreateProjectAudited(ctx, &tables.TableProject{Name: "Invalid open", MembershipMode: tables.ProjectMembershipOpen, SplitPolicy: tables.ProjectSplitEqual}, audit, outbox)
	require.Error(t, err)
}
