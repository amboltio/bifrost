package governance

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/configstore"
	configstoreTables "github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/maximhq/bifrost/framework/grant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeProjectStore struct {
	configstore.ProjectManagementStore
	byID    *configstoreTables.TableProject
	byName  *configstoreTables.TableProject
	member  bool
	err     error
	lookups []string
}

func (s *fakeProjectStore) GetProject(_ context.Context, id string) (*configstoreTables.TableProject, error) {
	s.lookups = append(s.lookups, "id:"+id)
	if s.err != nil {
		return nil, s.err
	}
	if s.byID == nil || s.byID.ID != id {
		return nil, nil
	}
	return s.byID, nil
}

func (s *fakeProjectStore) GetProjectByName(_ context.Context, name string) (*configstoreTables.TableProject, error) {
	s.lookups = append(s.lookups, "name:"+name)
	if s.err != nil {
		return nil, s.err
	}
	if s.byName == nil || s.byName.Name != name {
		return nil, nil
	}
	return s.byName, nil
}

func (s *fakeProjectStore) HasProjectMember(_ context.Context, projectID, userID string) (bool, error) {
	s.lookups = append(s.lookups, "members:"+projectID)
	if s.err != nil {
		return false, s.err
	}
	return s.member, nil
}

func testProject(id, name string) *configstoreTables.TableProject {
	return &configstoreTables.TableProject{
		ID: id, Name: name, Enabled: true,
		AccessRule:     configstoreTables.ProjectAccessRuleUnion,
		MembershipMode: configstoreTables.ProjectMembershipExplicit,
		AccountingMode: configstoreTables.ProjectAccountingBoth,
		SplitPolicy:    configstoreTables.ProjectSplitNone,
	}
}

func TestResolvePermitsAdmitsAndAttributesProject(t *testing.T) {
	project := testProject("project-1", "Atlas")
	project.AccessRule = configstoreTables.ProjectAccessRuleIntersect
	project.AllowedProviders = []string{"openai"}
	project.AllowedModels = []string{"gpt-4o"}
	store := &fakeProjectStore{
		byID:   project,
		member: true,
	}
	governanceStore := &LocalGovernanceStore{projectStore: store}
	ctx := presentUserCtx("user-1")
	ctx.SetValue(schemas.BifrostContextKeyRequestHeaders, map[string]string{schemas.HeaderGovernanceProjectID: "project-1"})

	bases, scoped, mode := governanceStore.ResolvePermits(ctx)

	require.Empty(t, bases)
	require.NotNil(t, scoped)
	assert.Equal(t, string(grant.PermitProject), scoped.Type())
	assert.Equal(t, project.ID, scoped.ID())
	assert.Equal(t, string(grant.Intersect), string(mode))
	assert.Equal(t, "project-1", bifrostString(ctx, schemas.BifrostContextKeyGovernanceProjectID))
	assert.Equal(t, "Atlas", bifrostString(ctx, schemas.BifrostContextKeyGovernanceProjectName))
	require.NotNil(t, ctx.Grant().Identity().Project())
	assert.Equal(t, project.ID, ctx.Grant().Identity().Project().ID)
	require.Len(t, scoped.ProviderPermits(), 1)
	assert.Equal(t, "openai", scoped.ProviderPermits()[0].Provider)
	assert.Equal(t, schemas.WhiteList{"gpt-4o"}, scoped.ProviderPermits()[0].AllowedModels)
	assert.Equal(t, schemas.WhiteList{"*"}, scoped.ProviderPermits()[0].KeyIDs)
}

func TestResolvePermitsRejectsUnavailableProjectPolicies(t *testing.T) {
	expired := time.Now().UTC().Add(-time.Minute)
	testCases := []struct {
		name       string
		project    *configstoreTables.TableProject
		projectErr error
	}{
		{name: "nonmember", project: testProject("p", "P")},
		{name: "expired", project: func() *configstoreTables.TableProject {
			p := testProject("p", "P")
			p.ExpiresAt = &expired
			p.MembershipMode = configstoreTables.ProjectMembershipOpen
			return p
		}()},
		{name: "disabled", project: func() *configstoreTables.TableProject {
			p := testProject("p", "P")
			p.Enabled = false
			p.MembershipMode = configstoreTables.ProjectMembershipOpen
			return p
		}()},
		{name: "unknown access rule", project: func() *configstoreTables.TableProject {
			p := testProject("p", "P")
			p.AccessRule = "unknown"
			p.MembershipMode = configstoreTables.ProjectMembershipOpen
			return p
		}()},
		{name: "unknown membership mode", project: func() *configstoreTables.TableProject {
			p := testProject("p", "P")
			p.MembershipMode = "unknown"
			return p
		}()},
		{name: "principal-only accounting is not wired", project: func() *configstoreTables.TableProject {
			p := testProject("p", "P")
			p.AccountingMode = configstoreTables.ProjectAccountingPrincipal
			p.MembershipMode = configstoreTables.ProjectMembershipOpen
			return p
		}()},
		{name: "all-provider model allowlist cannot be enforced", project: func() *configstoreTables.TableProject {
			p := testProject("p", "P")
			p.MembershipMode = configstoreTables.ProjectMembershipOpen
			p.AllowAllProviders = true
			p.AllowedModels = []string{"gpt-4o"}
			return p
		}()},
		{name: "equal split is not wired", project: func() *configstoreTables.TableProject {
			p := testProject("p", "P")
			p.SplitPolicy = configstoreTables.ProjectSplitEqual
			p.MembershipMode = configstoreTables.ProjectMembershipOpen
			return p
		}()},
		{name: "store failure", project: testProject("p", "P"), projectErr: errors.New("database unavailable")},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := &fakeProjectStore{byID: tc.project, err: tc.projectErr}
			governanceStore := &LocalGovernanceStore{projectStore: store}
			ctx := presentUserCtx("user-1")
			ctx.SetValue(schemas.BifrostContextKeyRequestHeaders, map[string]string{schemas.HeaderGovernanceProjectID: "p"})

			_, scoped, mode := governanceStore.ResolvePermits(ctx)

			assert.Nil(t, scoped)
			assert.Empty(t, mode)
			assert.Empty(t, bifrostString(ctx, schemas.BifrostContextKeyGovernanceProjectID))
			assert.Nil(t, ctx.Grant().Identity().Project())
		})
	}
}

func TestResolvePermitsExplicitMembershipDoesNotInferUserFromSharedKey(t *testing.T) {
	project := testProject("project-1", "Atlas")
	store := &fakeProjectStore{
		byID:   project,
		member: true,
	}
	governanceStore := &LocalGovernanceStore{projectStore: store}
	ctx := presentCtx("sk-bf-shared")
	ctx.SetValue(schemas.BifrostContextKeyRequestHeaders, map[string]string{schemas.HeaderGovernanceProjectID: project.ID})

	_, scoped, _ := governanceStore.ResolvePermits(ctx)

	assert.Nil(t, scoped)
	assert.Nil(t, ctx.Grant().Identity().User(), "a shared key does not establish which project member sent the request")
}

func TestResolvePermitsProjectIDHeaderWinsEvenWhenEmpty(t *testing.T) {
	project := testProject("project-1", "Atlas")
	project.MembershipMode = configstoreTables.ProjectMembershipOpen
	store := &fakeProjectStore{byName: project}
	governanceStore := &LocalGovernanceStore{projectStore: store}
	ctx := emptyCtx()
	ctx.SetValue(schemas.BifrostContextKeyRequestHeaders, map[string]string{
		schemas.HeaderGovernanceProjectID:   "",
		schemas.HeaderGovernanceProjectName: "Atlas",
	})

	_, scoped, mode := governanceStore.ResolvePermits(ctx)

	assert.Nil(t, scoped)
	assert.Empty(t, mode)
	assert.Equal(t, []string{"id:"}, store.lookups, "name must not be used when the ID header is present")
}

func TestResolvePermitsOpenProjectAllowsSharedKeyWithoutInferringUser(t *testing.T) {
	project := testProject("project-1", "Atlas")
	project.MembershipMode = configstoreTables.ProjectMembershipOpen
	project.AllowAllProviders = true
	store := &fakeProjectStore{byName: project}
	governanceStore := &LocalGovernanceStore{projectStore: store}
	governanceStore.storeVirtualKey("sk-bf-shared", buildVirtualKey("vk-shared", "sk-bf-shared", "Shared", true))
	ctx := presentCtx("sk-bf-shared")
	ctx.SetValue(schemas.BifrostContextKeyRequestHeaders, map[string]string{schemas.HeaderGovernanceProjectName: "Atlas"})

	bases, scoped, mode := governanceStore.ResolvePermits(ctx)

	require.Len(t, bases, 1)
	assert.Equal(t, "vk-shared", bases[0].ID())
	require.NotNil(t, scoped, "open membership should allow the explicitly open project")
	assert.Equal(t, string(grant.Union), string(mode))
	assert.Nil(t, ctx.Grant().Identity().User(), "a key must not imply its assigned user")
	require.NotNil(t, ctx.Grant().Identity().Project())
	assert.Equal(t, project.ID, ctx.Grant().Identity().Project().ID)
}

func TestResolvePermitsDoesNotLetProjectRescueUnknownVirtualKey(t *testing.T) {
	project := testProject("project-1", "Atlas")
	project.MembershipMode = configstoreTables.ProjectMembershipOpen
	store := &fakeProjectStore{byName: project}
	governanceStore := &LocalGovernanceStore{projectStore: store}
	ctx := presentCtx("sk-bf-missing")
	ctx.SetValue(schemas.BifrostContextKeyRequestHeaders, map[string]string{schemas.HeaderGovernanceProjectName: "Atlas"})

	bases, scoped, mode := governanceStore.ResolvePermits(ctx)

	assert.Empty(t, bases)
	assert.Nil(t, scoped)
	assert.Empty(t, mode)
	assert.Empty(t, bifrostString(ctx, schemas.BifrostContextKeyGovernanceProjectID))
	assert.Empty(t, store.lookups, "an invalid credential must be refused before resolving a project")
}

func bifrostString(ctx *schemas.BifrostContext, key schemas.BifrostContextKey) string {
	value, _ := ctx.Value(key).(string)
	return value
}
