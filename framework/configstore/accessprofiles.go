package configstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"gorm.io/gorm"
)

type AccessProfileQueryParams struct {
	Search string
	Limit  int
	Offset int
}

// AccessProfileManagementStore is the durable OSS contract for reusable
// provider/model/MCP allow-lists and their source-aware user and role assignments.
type AccessProfileManagementStore interface {
	ListAccessProfiles(ctx context.Context, params AccessProfileQueryParams) ([]tables.TableAccessProfile, int64, error)
	GetAccessProfile(ctx context.Context, id string) (*tables.TableAccessProfile, error)
	CreateAccessProfileAudited(ctx context.Context, profile *tables.TableAccessProfile, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) (*tables.TableAccessProfile, error)
	UpdateAccessProfileAudited(ctx context.Context, id, name, description string, enabled, allowAllProviders bool, providers, models []string, providerConfigs []tables.AccessProfileProviderConfig, mcpTools []string, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) (*tables.TableAccessProfile, error)
	DeleteAccessProfileAudited(ctx context.Context, id string, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) error
	ListUserAccessProfileAssignments(ctx context.Context, userID string) ([]tables.TableUserAccessProfileAssignment, error)
	ListRoleAccessProfileAssignments(ctx context.Context, roleID string) ([]tables.TableRoleAccessProfileAssignment, error)
	ReplaceManualUserAccessProfilesAudited(ctx context.Context, userID string, profileIDs []string, assignedByUserID *string, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) error
	ReplaceManualRoleAccessProfilesAudited(ctx context.Context, roleID string, profileIDs []string, assignedByUserID *string, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) error
}

func (s *RDBConfigStore) ListAccessProfiles(ctx context.Context, params AccessProfileQueryParams) ([]tables.TableAccessProfile, int64, error) {
	limit := params.Limit
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	query := s.DB().WithContext(ctx).Model(&tables.TableAccessProfile{})
	if search := strings.TrimSpace(params.Search); search != "" {
		needle := "%" + strings.ToLower(search) + "%"
		query = query.Where("LOWER(name) LIKE ? OR LOWER(description) LIKE ?", needle, needle)
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var profiles []tables.TableAccessProfile
	if err := query.Order("name ASC, id ASC").Limit(limit).Offset(max(params.Offset, 0)).Find(&profiles).Error; err != nil {
		return nil, 0, err
	}
	return profiles, total, nil
}

func (s *RDBConfigStore) GetAccessProfile(ctx context.Context, id string) (*tables.TableAccessProfile, error) {
	var profile tables.TableAccessProfile
	if err := s.DB().WithContext(ctx).First(&profile, "id = ?", strings.TrimSpace(id)).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &profile, nil
}

func (s *RDBConfigStore) CreateAccessProfileAudited(ctx context.Context, profile *tables.TableAccessProfile, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) (*tables.TableAccessProfile, error) {
	if profile == nil {
		return nil, fmt.Errorf("access profile is required")
	}
	profile.ID = strings.TrimSpace(profile.ID)
	if profile.ID == "" {
		profile.ID = uuid.NewString()
	}
	profile.Name = strings.TrimSpace(profile.Name)
	profile.Description = strings.TrimSpace(profile.Description)
	if profile.Name == "" {
		return nil, fmt.Errorf("access profile name is required")
	}
	profile.AllowedProviders = normalizeStringList(profile.AllowedProviders)
	profile.AllowedModels = normalizeStringList(profile.AllowedModels)
	profile.AllowedMCPTools = normalizeStringList(profile.AllowedMCPTools)
	providerConfigs, err := NormalizeAccessProfileProviderConfigs(profile.ProviderConfigs)
	if err != nil {
		return nil, err
	}
	profile.ProviderConfigs = providerConfigs
	returnProfile := profile
	err = s.ApplyAuditedChange(ctx, auditEvent, outboxEvent, func(tx *gorm.DB) error {
		if err := tx.WithContext(ctx).Create(returnProfile).Error; err != nil {
			return s.parseGormError(err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return returnProfile, nil
}

func (s *RDBConfigStore) UpdateAccessProfileAudited(ctx context.Context, id, name, description string, enabled, allowAllProviders bool, providers, models []string, providerConfigs []tables.AccessProfileProviderConfig, mcpTools []string, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) (*tables.TableAccessProfile, error) {
	id, name, description = strings.TrimSpace(id), strings.TrimSpace(name), strings.TrimSpace(description)
	if id == "" || name == "" {
		return nil, ErrNotFound
	}
	providers, models, mcpTools = normalizeStringList(providers), normalizeStringList(models), normalizeStringList(mcpTools)
	providerConfigs, err := NormalizeAccessProfileProviderConfigs(providerConfigs)
	if err != nil {
		return nil, err
	}
	providersJSON, err := json.Marshal(providers)
	if err != nil {
		return nil, err
	}
	modelsJSON, err := json.Marshal(models)
	if err != nil {
		return nil, err
	}
	providerConfigsJSON, err := json.Marshal(providerConfigs)
	if err != nil {
		return nil, err
	}
	mcpToolsJSON, err := json.Marshal(mcpTools)
	if err != nil {
		return nil, err
	}
	var profile tables.TableAccessProfile
	err = s.ApplyAuditedChange(ctx, auditEvent, outboxEvent, func(tx *gorm.DB) error {
		if err := dbForUpdate(tx).First(&profile, "id = ?", id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		if err := tx.WithContext(ctx).Model(&tables.TableAccessProfile{}).Where("id = ?", id).Updates(map[string]any{
			"name": name, "description": description, "enabled": enabled, "allow_all_providers": allowAllProviders,
			"allowed_providers": string(providersJSON), "allowed_models": string(modelsJSON), "provider_configs": string(providerConfigsJSON), "allowed_mcp_tools": string(mcpToolsJSON),
			"updated_at": time.Now().UTC(),
		}).Error; err != nil {
			return s.parseGormError(err)
		}
		profile.Name, profile.Description, profile.Enabled, profile.AllowAllProviders = name, description, enabled, allowAllProviders
		profile.AllowedProviders, profile.AllowedModels, profile.ProviderConfigs, profile.AllowedMCPTools = providers, models, providerConfigs, mcpTools
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &profile, nil
}

// NormalizeAccessProfileProviderConfigs validates and canonicalizes provider-specific policy rows.
func NormalizeAccessProfileProviderConfigs(configs []tables.AccessProfileProviderConfig) ([]tables.AccessProfileProviderConfig, error) {
	result := make([]tables.AccessProfileProviderConfig, 0, len(configs))
	seen := make(map[string]struct{}, len(configs))
	for _, config := range configs {
		config.ProviderName = strings.ToLower(strings.TrimSpace(config.ProviderName))
		if config.ProviderName == "" {
			return nil, fmt.Errorf("provider name is required for access profile provider config")
		}
		canonicalName := strings.ToLower(config.ProviderName)
		if _, exists := seen[canonicalName]; exists {
			return nil, fmt.Errorf("duplicate access profile provider config for %q", config.ProviderName)
		}
		seen[canonicalName] = struct{}{}
		config.AllowedModels = normalizeStringList(config.AllowedModels)
		config.BlacklistedModels = normalizeStringList(config.BlacklistedModels)
		config.KeyIDs = normalizeStringList(config.KeyIDs)
		result = append(result, config)
	}
	return result, nil
}

func (s *RDBConfigStore) DeleteAccessProfileAudited(ctx context.Context, id string, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return ErrNotFound
	}
	return s.ApplyAuditedChange(ctx, auditEvent, outboxEvent, func(tx *gorm.DB) error {
		var profile tables.TableAccessProfile
		if err := dbForUpdate(tx).First(&profile, "id = ?", id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		var assignments int64
		if err := tx.Model(&tables.TableUserAccessProfileAssignment{}).Where("access_profile_id = ?", id).Count(&assignments).Error; err != nil {
			return err
		}
		if assignments > 0 {
			return ErrAccessProfileInUse
		}
		if err := tx.Model(&tables.TableRoleAccessProfileAssignment{}).Where("access_profile_id = ?", id).Count(&assignments).Error; err != nil {
			return err
		}
		if assignments > 0 {
			return ErrAccessProfileInUse
		}
		return tx.Delete(&profile).Error
	})
}

func (s *RDBConfigStore) ListUserAccessProfileAssignments(ctx context.Context, userID string) ([]tables.TableUserAccessProfileAssignment, error) {
	var assignments []tables.TableUserAccessProfileAssignment
	err := s.DB().WithContext(ctx).Where("user_id = ?", strings.TrimSpace(userID)).Order("created_at ASC, id ASC").Find(&assignments).Error
	return assignments, err
}

func (s *RDBConfigStore) ListRoleAccessProfileAssignments(ctx context.Context, roleID string) ([]tables.TableRoleAccessProfileAssignment, error) {
	var assignments []tables.TableRoleAccessProfileAssignment
	err := s.DB().WithContext(ctx).Where("role_id = ?", strings.TrimSpace(roleID)).Order("created_at ASC, id ASC").Find(&assignments).Error
	return assignments, err
}

func (s *RDBConfigStore) ReplaceManualUserAccessProfilesAudited(ctx context.Context, userID string, profileIDs []string, assignedByUserID *string, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) error {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return ErrNotFound
	}
	ids := normalizeStringList(profileIDs)
	return s.ApplyAuditedChange(ctx, auditEvent, outboxEvent, func(tx *gorm.DB) error {
		var userCount int64
		if err := tx.Model(&tables.TableUser{}).Where("id = ?", userID).Count(&userCount).Error; err != nil {
			return err
		}
		if userCount == 0 {
			return ErrNotFound
		}
		if len(ids) > 0 {
			var profileCount int64
			if err := tx.Model(&tables.TableAccessProfile{}).Where("id IN ?", ids).Count(&profileCount).Error; err != nil {
				return err
			}
			if profileCount != int64(len(ids)) {
				return ErrNotFound
			}
		}
		if err := tx.Where("user_id = ? AND source = ?", userID, tables.AccessProfileSourceManual).Delete(&tables.TableUserAccessProfileAssignment{}).Error; err != nil {
			return err
		}
		for _, profileID := range ids {
			assignment := &tables.TableUserAccessProfileAssignment{ID: uuid.NewString(), UserID: userID, AccessProfileID: profileID, Source: tables.AccessProfileSourceManual, AssignedByUserID: assignedByUserID}
			if err := tx.Create(assignment).Error; err != nil {
				return s.parseGormError(err)
			}
		}
		return nil
	})
}

func (s *RDBConfigStore) ReplaceManualRoleAccessProfilesAudited(ctx context.Context, roleID string, profileIDs []string, assignedByUserID *string, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) error {
	roleID = strings.TrimSpace(roleID)
	if roleID == "" {
		return ErrNotFound
	}
	ids := normalizeStringList(profileIDs)
	return s.ApplyAuditedChange(ctx, auditEvent, outboxEvent, func(tx *gorm.DB) error {
		var roleCount int64
		if err := tx.Model(&tables.TableRole{}).Where("id = ?", roleID).Count(&roleCount).Error; err != nil {
			return err
		}
		if roleCount == 0 {
			return ErrNotFound
		}
		if len(ids) > 0 {
			var profileCount int64
			if err := tx.Model(&tables.TableAccessProfile{}).Where("id IN ?", ids).Count(&profileCount).Error; err != nil {
				return err
			}
			if profileCount != int64(len(ids)) {
				return ErrNotFound
			}
		}
		if err := tx.Where("role_id = ? AND source = ?", roleID, tables.RoleAccessProfileSourceManual).Delete(&tables.TableRoleAccessProfileAssignment{}).Error; err != nil {
			return err
		}
		for _, profileID := range ids {
			assignment := &tables.TableRoleAccessProfileAssignment{ID: uuid.NewString(), RoleID: roleID, AccessProfileID: profileID, Source: tables.RoleAccessProfileSourceManual, AssignedByUserID: assignedByUserID}
			if err := tx.Create(assignment).Error; err != nil {
				return s.parseGormError(err)
			}
		}
		return nil
	})
}

func normalizeStringList(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	slices.Sort(result)
	return result
}
