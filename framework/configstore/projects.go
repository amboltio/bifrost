package configstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"gorm.io/gorm"
)

type ProjectQueryParams struct {
	Search string
	Limit  int
	Offset int
}

type ProjectManagementStore interface {
	ListProjects(ctx context.Context, params ProjectQueryParams) ([]tables.TableProject, int64, error)
	GetProject(ctx context.Context, id string) (*tables.TableProject, error)
	GetProjectByName(ctx context.Context, name string) (*tables.TableProject, error)
	HasProjectMember(ctx context.Context, projectID, userID string) (bool, error)
	CreateProjectAudited(ctx context.Context, project *tables.TableProject, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) (*tables.TableProject, error)
	UpdateProjectAudited(ctx context.Context, id, name, description string, enabled bool, expiresAt *time.Time, accessRule, membershipMode, accountingMode, splitPolicy string, allowAllProviders bool, providers, models []string, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) (*tables.TableProject, error)
	DeleteProjectAudited(ctx context.Context, id string, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) error
	ListProjectMembers(ctx context.Context, projectID string) ([]tables.TableProjectMember, error)
	ReplaceManualProjectMembersAudited(ctx context.Context, projectID string, userIDs []string, assignedByUserID *string, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) error
}

func (s *RDBConfigStore) ListProjects(ctx context.Context, params ProjectQueryParams) ([]tables.TableProject, int64, error) {
	limit := params.Limit
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	query := s.DB().WithContext(ctx).Model(&tables.TableProject{})
	if search := strings.TrimSpace(params.Search); search != "" {
		needle := "%" + strings.ToLower(search) + "%"
		query = query.Where("LOWER(name) LIKE ? OR LOWER(description) LIKE ?", needle, needle)
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var projects []tables.TableProject
	if err := query.Order("name ASC, id ASC").Limit(limit).Offset(max(params.Offset, 0)).Find(&projects).Error; err != nil {
		return nil, 0, err
	}
	return projects, total, nil
}

func (s *RDBConfigStore) GetProject(ctx context.Context, id string) (*tables.TableProject, error) {
	var project tables.TableProject
	if err := s.DB().WithContext(ctx).First(&project, "id = ?", strings.TrimSpace(id)).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &project, nil
}

// GetProjectByName resolves a project by its exact globally unique name. Request headers must not
// use the fuzzy search used by the management list endpoint: a description or substring match
// would otherwise choose a project the caller did not name.
func (s *RDBConfigStore) GetProjectByName(ctx context.Context, name string) (*tables.TableProject, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, nil
	}
	var project tables.TableProject
	if err := s.DB().WithContext(ctx).First(&project, "name = ?", name).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &project, nil
}

func validateProject(project *tables.TableProject) error {
	if project == nil {
		return fmt.Errorf("project is required")
	}
	if project.Name = strings.TrimSpace(project.Name); project.Name == "" {
		return fmt.Errorf("project name is required")
	}
	if project.AccessRule == "" {
		project.AccessRule = tables.ProjectAccessRuleUnion
	}
	if project.MembershipMode == "" {
		project.MembershipMode = tables.ProjectMembershipExplicit
	}
	if project.AccountingMode == "" {
		project.AccountingMode = tables.ProjectAccountingBoth
	}
	if project.SplitPolicy == "" {
		project.SplitPolicy = tables.ProjectSplitNone
	}
	if project.AccessRule != tables.ProjectAccessRuleUnion && project.AccessRule != tables.ProjectAccessRuleIntersect {
		return fmt.Errorf("invalid project access_rule")
	}
	if project.MembershipMode != tables.ProjectMembershipExplicit && project.MembershipMode != tables.ProjectMembershipOpen {
		return fmt.Errorf("invalid project membership_mode")
	}
	if project.AccountingMode != tables.ProjectAccountingBoth && project.AccountingMode != tables.ProjectAccountingProject && project.AccountingMode != tables.ProjectAccountingPrincipal {
		return fmt.Errorf("invalid project accounting_mode")
	}
	if project.SplitPolicy != tables.ProjectSplitNone && project.SplitPolicy != tables.ProjectSplitEqual {
		return fmt.Errorf("invalid project split_policy")
	}
	if project.MembershipMode == tables.ProjectMembershipOpen && project.SplitPolicy != tables.ProjectSplitNone {
		return fmt.Errorf("open projects cannot split budgets equally")
	}
	project.Description = strings.TrimSpace(project.Description)
	project.AllowedProviders = normalizeStringList(project.AllowedProviders)
	project.AllowedModels = normalizeStringList(project.AllowedModels)
	return nil
}

func (s *RDBConfigStore) CreateProjectAudited(ctx context.Context, project *tables.TableProject, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) (*tables.TableProject, error) {
	if project == nil {
		return nil, fmt.Errorf("project is required")
	}
	if project.ID = strings.TrimSpace(project.ID); project.ID == "" {
		project.ID = uuid.NewString()
	}
	if err := validateProject(project); err != nil {
		return nil, err
	}
	err := s.ApplyAuditedChange(ctx, auditEvent, outboxEvent, func(tx *gorm.DB) error {
		if err := tx.WithContext(ctx).Create(project).Error; err != nil {
			return s.parseGormError(err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return project, nil
}

func (s *RDBConfigStore) UpdateProjectAudited(ctx context.Context, id, name, description string, enabled bool, expiresAt *time.Time, accessRule, membershipMode, accountingMode, splitPolicy string, allowAllProviders bool, providers, models []string, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) (*tables.TableProject, error) {
	providers, models = normalizeStringList(providers), normalizeStringList(models)
	project := &tables.TableProject{Name: name, Description: description, Enabled: enabled, ExpiresAt: expiresAt, AccessRule: accessRule, MembershipMode: membershipMode, AccountingMode: accountingMode, SplitPolicy: splitPolicy, AllowAllProviders: allowAllProviders, AllowedProviders: providers, AllowedModels: models}
	if err := validateProject(project); err != nil {
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
	var current tables.TableProject
	err = s.ApplyAuditedChange(ctx, auditEvent, outboxEvent, func(tx *gorm.DB) error {
		if err := dbForUpdate(tx).First(&current, "id = ?", strings.TrimSpace(id)).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		if err := tx.WithContext(ctx).Model(&tables.TableProject{}).Where("id = ?", current.ID).Updates(map[string]any{"name": project.Name, "description": project.Description, "enabled": project.Enabled, "expires_at": project.ExpiresAt, "access_rule": project.AccessRule, "membership_mode": project.MembershipMode, "accounting_mode": project.AccountingMode, "split_policy": project.SplitPolicy, "allow_all_providers": project.AllowAllProviders, "allowed_providers": string(providersJSON), "allowed_models": string(modelsJSON), "updated_at": time.Now().UTC()}).Error; err != nil {
			return s.parseGormError(err)
		}
		project.ID = current.ID
		project.CreatedByUserID = current.CreatedByUserID
		project.CreatedAt = current.CreatedAt
		project.UpdatedAt = time.Now().UTC()
		current = *project
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &current, nil
}

func (s *RDBConfigStore) DeleteProjectAudited(ctx context.Context, id string, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return ErrNotFound
	}
	return s.ApplyAuditedChange(ctx, auditEvent, outboxEvent, func(tx *gorm.DB) error {
		var project tables.TableProject
		if err := dbForUpdate(tx).First(&project, "id = ?", id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		var members int64
		if err := tx.Model(&tables.TableProjectMember{}).Where("project_id = ?", id).Count(&members).Error; err != nil {
			return err
		}
		if members > 0 {
			return ErrProjectInUse
		}
		return tx.Delete(&project).Error
	})
}

func (s *RDBConfigStore) ListProjectMembers(ctx context.Context, projectID string) ([]tables.TableProjectMember, error) {
	var members []tables.TableProjectMember
	err := s.DB().WithContext(ctx).Where("project_id = ?", strings.TrimSpace(projectID)).Order("created_at ASC, id ASC").Find(&members).Error
	return members, err
}

// HasProjectMember checks one exact membership without loading the full project roster on the
// inference path.
func (s *RDBConfigStore) HasProjectMember(ctx context.Context, projectID, userID string) (bool, error) {
	projectID = strings.TrimSpace(projectID)
	userID = strings.TrimSpace(userID)
	if projectID == "" || userID == "" {
		return false, nil
	}
	var count int64
	err := s.DB().WithContext(ctx).Model(&tables.TableProjectMember{}).
		Where("project_id = ? AND user_id = ?", projectID, userID).
		Count(&count).Error
	return count > 0, err
}

func (s *RDBConfigStore) ReplaceManualProjectMembersAudited(ctx context.Context, projectID string, userIDs []string, assignedByUserID *string, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) error {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return ErrNotFound
	}
	ids := normalizeStringList(userIDs)
	return s.ApplyAuditedChange(ctx, auditEvent, outboxEvent, func(tx *gorm.DB) error {
		var count int64
		if err := tx.Model(&tables.TableProject{}).Where("id = ?", projectID).Count(&count).Error; err != nil {
			return err
		}
		if count == 0 {
			return ErrNotFound
		}
		if len(ids) > 0 {
			if err := tx.Model(&tables.TableUser{}).Where("id IN ?", ids).Count(&count).Error; err != nil {
				return err
			}
			if count != int64(len(ids)) {
				return ErrNotFound
			}
		}
		if err := tx.Where("project_id = ? AND source = ?", projectID, "manual").Delete(&tables.TableProjectMember{}).Error; err != nil {
			return err
		}
		for _, userID := range ids {
			member := &tables.TableProjectMember{ID: uuid.NewString(), ProjectID: projectID, UserID: userID, Source: "manual", AssignedByUserID: assignedByUserID}
			if err := tx.Create(member).Error; err != nil {
				return s.parseGormError(err)
			}
		}
		return nil
	})
}
