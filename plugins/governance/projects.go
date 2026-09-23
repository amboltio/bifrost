package governance

import (
	"strings"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/configstore"
	configstoreTables "github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/maximhq/bifrost/framework/grant"
)

func projectManagementStore(store configstore.ConfigStore) configstore.ProjectManagementStore {
	if store == nil {
		return nil
	}
	projects, _ := store.(configstore.ProjectManagementStore)
	return projects
}

func (gs *LocalGovernanceStore) resolveProjectPermit(ctx *schemas.BifrostContext) (schemas.Permit, grant.CompositionMode) {
	if ctx == nil || gs.projectStore == nil {
		return nil, ""
	}
	headers, _ := ctx.Value(schemas.BifrostContextKeyRequestHeaders).(map[string]string)
	projectID, idPresent := headers[schemas.HeaderGovernanceProjectID]
	projectName, namePresent := headers[schemas.HeaderGovernanceProjectName]
	if !idPresent && !namePresent {
		return nil, ""
	}

	var project *configstoreTables.TableProject
	var err error
	if idPresent {
		project, err = gs.projectStore.GetProject(ctx, strings.TrimSpace(projectID))
	} else {
		project, err = gs.projectStore.GetProjectByName(ctx, strings.TrimSpace(projectName))
	}
	if err != nil {
		if gs.logger != nil {
			gs.logger.Error("failed to resolve request project: %v", err)
		}
		return nil, ""
	}
	if project == nil || !project.Enabled || project.ID == "" ||
		(project.ExpiresAt != nil && !project.ExpiresAt.After(time.Now().UTC())) {
		return nil, ""
	}

	var mode grant.CompositionMode
	switch project.AccessRule {
	case configstoreTables.ProjectAccessRuleUnion:
		mode = grant.Union
	case configstoreTables.ProjectAccessRuleIntersect:
		mode = grant.Intersect
	default:
		return nil, ""
	}

	// Project-only/principal-only accounting and equal-split redivision are not yet implemented by
	// the OSS request tracker. Refuse those policies until their ledger semantics can be honored.
	if project.AccountingMode != configstoreTables.ProjectAccountingBoth || project.SplitPolicy != configstoreTables.ProjectSplitNone {
		return nil, ""
	}
	if project.AllowAllProviders && len(project.AllowedModels) > 0 {
		// The permit contract can constrain named providers' models, but cannot express one global
		// model allowlist over every provider. Do not broaden that policy to unrestricted models.
		return nil, ""
	}

	switch project.MembershipMode {
	case configstoreTables.ProjectMembershipOpen:
	case configstoreTables.ProjectMembershipExplicit:
		requestGrant := ctx.Grant()
		if requestGrant == nil {
			return nil, ""
		}
		identity := requestGrant.Identity()
		if identity == nil || identity.User() == nil || strings.TrimSpace(identity.User().ID) == "" {
			return nil, ""
		}
		member, err := gs.projectStore.HasProjectMember(ctx, project.ID, identity.User().ID)
		if err != nil {
			if gs.logger != nil {
				gs.logger.Error("failed to resolve request project membership: %v", err)
			}
			return nil, ""
		}
		if !member {
			return nil, ""
		}
	default:
		return nil, ""
	}

	permit := projectPermit(project)
	stampProjectIdentity(ctx, project)
	return permit, mode
}

func projectPermit(project *configstoreTables.TableProject) schemas.Permit {
	if project == nil {
		return nil
	}
	models := schemas.WhiteList(project.AllowedModels)
	if len(models) == 0 {
		models = schemas.WhiteList{"*"}
	}
	providerPermits := make([]schemas.ProviderPermit, 0, len(project.AllowedProviders))
	for _, provider := range project.AllowedProviders {
		provider = strings.TrimSpace(provider)
		if provider == "" {
			continue
		}
		providerPermits = append(providerPermits, schemas.ProviderPermit{
			Provider:      provider,
			AllowedModels: models,
			KeyIDs:        schemas.WhiteList{"*"},
		})
	}
	return grant.NewPermit(grant.PermitProject, project.ID, project.Name, true, false, providerPermits, nil,
		grant.WithAllowAllProviders(project.AllowAllProviders))
}

func stampProjectIdentity(ctx *schemas.BifrostContext, project *configstoreTables.TableProject) {
	if ctx == nil || project == nil {
		return
	}
	ctx.SetValue(schemas.BifrostContextKeyGovernanceProjectID, project.ID)
	ctx.SetValue(schemas.BifrostContextKeyGovernanceProjectName, project.Name)
	if requestGrant := ctx.Grant(); requestGrant != nil {
		if current := requestGrant.Identity(); current != nil {
			projectRef := &schemas.EntityRef{ID: project.ID, Name: project.Name}
			requestGrant.SetIdentity(grant.NewIdentity(current.Credential(), current.User(), current.VirtualKey(), current.Teams(), current.Customers(), current.BusinessUnits(), projectRef))
		}
	}
}
