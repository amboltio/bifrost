package configstore

import (
	"context"
	"strings"

	"github.com/google/uuid"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"gorm.io/gorm"
)

// UserTeamMembershipStore is the narrow organization-assignment contract.
// Source-aware replacement is used by both the dashboard and future IdP
// reconciliation jobs so one source cannot erase another source's grants.
type UserTeamMembershipStore interface {
	ListUserTeamMemberships(ctx context.Context, userID string) ([]tables.TableUserTeamMembership, error)
	ReplaceManualUserTeamMembershipsAudited(ctx context.Context, userID string, teamIDs []string, assignedByUserID *string, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) error
}

func (s *RDBConfigStore) ListUserTeamMemberships(ctx context.Context, userID string) ([]tables.TableUserTeamMembership, error) {
	if strings.TrimSpace(userID) == "" {
		return []tables.TableUserTeamMembership{}, nil
	}
	var memberships []tables.TableUserTeamMembership
	if err := s.DB().WithContext(ctx).Preload("Team").Where("user_id = ?", userID).Order("team_id ASC, source ASC").Find(&memberships).Error; err != nil {
		return nil, err
	}
	return memberships, nil
}

func (s *RDBConfigStore) ReplaceManualUserTeamMembershipsAudited(ctx context.Context, userID string, teamIDs []string, assignedByUserID *string, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) error {
	if strings.TrimSpace(userID) == "" {
		return ErrNotFound
	}
	teamIDs = normalizedStringIDs(teamIDs)
	return s.ApplyAuditedChange(ctx, auditEvent, outboxEvent, func(tx *gorm.DB) error {
		if _, err := lockedUser(tx, userID); err != nil {
			return err
		}
		if len(teamIDs) > 0 {
			var count int64
			if err := tx.Model(&tables.TableTeam{}).Where("id IN ?", teamIDs).Count(&count).Error; err != nil {
				return err
			}
			if count != int64(len(teamIDs)) {
				return ErrNotFound
			}
		}
		if err := tx.Where("user_id = ? AND source = ?", userID, tables.UserTeamSourceManual).Delete(&tables.TableUserTeamMembership{}).Error; err != nil {
			return err
		}
		for _, teamID := range teamIDs {
			if err := tx.Create(&tables.TableUserTeamMembership{
				ID: uuid.NewString(), UserID: userID, TeamID: teamID,
				Source: tables.UserTeamSourceManual, AssignedByUserID: assignedByUserID,
			}).Error; err != nil {
				return s.parseGormError(err)
			}
		}
		return nil
	})
}

func normalizedStringIDs(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func userTeamIDs(memberships []tables.TableUserTeamMembership) []string {
	ids := make([]string, 0, len(memberships))
	for _, membership := range memberships {
		if strings.TrimSpace(membership.TeamID) != "" {
			ids = append(ids, membership.TeamID)
		}
	}
	return ids
}
