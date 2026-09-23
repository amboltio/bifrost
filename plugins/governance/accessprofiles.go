package governance

import (
	"sort"
	"strings"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/configstore"
	configstoreTables "github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/maximhq/bifrost/framework/grant"
)

func accessProfileManagementStore(store configstore.ConfigStore) configstore.AccessProfileManagementStore {
	if store == nil {
		return nil
	}
	profiles, _ := store.(configstore.AccessProfileManagementStore)
	return profiles
}

// resolveUserAccessProfilePermits adds direct user assignments to the caller's base permits.
// It reads only the verified user on the request grant; virtual-key assignments never identify a
// person because a shared key does not say which user sent the request.
func (gs *LocalGovernanceStore) resolveUserAccessProfilePermits(ctx *schemas.BifrostContext) []schemas.Permit {
	if ctx == nil || gs.profileStore == nil {
		return nil
	}
	requestGrant := ctx.Grant()
	if requestGrant == nil {
		return nil
	}
	identity := requestGrant.Identity()
	if identity == nil || identity.User() == nil {
		return nil
	}
	userID := strings.TrimSpace(identity.User().ID)
	if userID == "" {
		return nil
	}

	assignments, err := gs.profileStore.ListUserAccessProfileAssignments(ctx, userID)
	if err != nil {
		if gs.logger != nil {
			gs.logger.Error("failed to resolve user access-profile assignments: %v", err)
		}
		return nil
	}

	seen := make(map[string]struct{}, len(assignments))
	permits := make([]schemas.Permit, 0, len(assignments))
	clientNames := map[string]string(nil)
	if gs.inMemoryStore != nil {
		clientNames = gs.inMemoryStore.GetMCPClientNames()
	}
	for _, assignment := range assignments {
		profileID := strings.TrimSpace(assignment.AccessProfileID)
		if profileID == "" {
			continue
		}
		if _, duplicate := seen[profileID]; duplicate {
			continue
		}
		seen[profileID] = struct{}{}

		profile, err := gs.profileStore.GetAccessProfile(ctx, profileID)
		if err != nil {
			if gs.logger != nil {
				gs.logger.Error("failed to resolve assigned access profile %s: %v", profileID, err)
			}
			return nil
		}
		if profile == nil || !profile.Enabled {
			continue
		}
		if profile.AllowAllProviders && len(profile.AllowedModels) > 0 {
			// The persisted profile shape cannot express a single model allowlist across every
			// provider. Skip the unusable profile rather than widening it to all models.
			continue
		}
		permits = append(permits, accessProfilePermit(profile, clientNames))
	}
	return permits
}

func accessProfilePermit(profile *configstoreTables.TableAccessProfile, clientNames map[string]string) schemas.Permit {
	models := normalizedPermitList(profile.AllowedModels)
	if len(models) == 0 {
		models = schemas.WhiteList{"*"}
	}
	providers := make([]schemas.ProviderPermit, 0, len(profile.AllowedProviders))
	seenProviders := make(map[string]struct{}, len(profile.AllowedProviders))
	for _, provider := range profile.AllowedProviders {
		provider = strings.TrimSpace(provider)
		if provider == "" {
			continue
		}
		if _, duplicate := seenProviders[provider]; duplicate {
			continue
		}
		seenProviders[provider] = struct{}{}
		providers = append(providers, schemas.ProviderPermit{
			Provider:      provider,
			AllowedModels: models,
			KeyIDs:        schemas.WhiteList{"*"},
		})
	}
	return grant.NewPermit(
		grant.PermitAccessProfile,
		profile.ID,
		profile.Name,
		true,
		false,
		providers,
		accessProfileMCPPermits(profile.AllowedMCPTools, clientNames),
		grant.WithAllowAllProviders(profile.AllowAllProviders),
	)
}

func normalizedPermitList(values []string) schemas.WhiteList {
	result := make(schemas.WhiteList, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func accessProfileMCPPermits(patterns []string, clientNames map[string]string) []schemas.MCPPermit {
	type client struct {
		id   string
		name string
	}
	clients := make([]client, 0, len(clientNames))
	for id, name := range clientNames {
		id, name = strings.TrimSpace(id), strings.TrimSpace(name)
		if name != "" {
			clients = append(clients, client{id: id, name: name})
		}
	}
	// Longest names win when one MCP client name is a prefix of another.
	sort.Slice(clients, func(i, j int) bool {
		if len(clients[i].name) == len(clients[j].name) {
			return clients[i].name < clients[j].name
		}
		return len(clients[i].name) > len(clients[j].name)
	})

	permits := make([]schemas.MCPPermit, 0)
	permitByID := make(map[string]int)
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		for _, candidate := range clients {
			tool, matched := strings.CutPrefix(pattern, candidate.name+"-")
			if !matched || tool == "" {
				continue
			}
			key := candidate.id
			if key == "" {
				key = candidate.name
			}
			index, exists := permitByID[key]
			if !exists {
				index = len(permits)
				permitByID[key] = index
				permits = append(permits, schemas.MCPPermit{Client: candidate.id, ClientName: candidate.name})
			}
			tools := &permits[index].Tools
			if tool == "*" {
				*tools = schemas.WhiteList{"*"}
			} else if !tools.IsUnrestricted() {
				found := false
				for _, existing := range *tools {
					if existing == tool {
						found = true
						break
					}
				}
				if !found {
					*tools = append(*tools, tool)
				}
			}
			break
		}
	}
	return permits
}
