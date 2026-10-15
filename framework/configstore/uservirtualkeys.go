package configstore

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"gorm.io/gorm"
)

type UserVirtualKeyAssignmentStore interface {
	ListUserVirtualKeyAssignments(ctx context.Context, userID string) ([]tables.TableUserVirtualKeyAssignment, error)
	ListVirtualKeyUserAssignments(ctx context.Context, virtualKeyID string) ([]tables.TableUserVirtualKeyAssignment, error)
	ReplaceManualUserVirtualKeyAssignmentsAudited(ctx context.Context, userID string, virtualKeyIDs []string, assignedByUserID *string, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) error
}

func (s *RDBConfigStore) ListUserVirtualKeyAssignments(ctx context.Context, userID string) ([]tables.TableUserVirtualKeyAssignment, error) {
	var assignments []tables.TableUserVirtualKeyAssignment
	err := s.DB().WithContext(ctx).Where("user_id = ? AND revoked_at IS NULL", strings.TrimSpace(userID)).Order("created_at ASC, id ASC").Find(&assignments).Error
	return assignments, err
}

func (s *RDBConfigStore) ListVirtualKeyUserAssignments(ctx context.Context, virtualKeyID string) ([]tables.TableUserVirtualKeyAssignment, error) {
	var assignments []tables.TableUserVirtualKeyAssignment
	err := s.DB().WithContext(ctx).Where("virtual_key_id = ? AND revoked_at IS NULL", strings.TrimSpace(virtualKeyID)).Order("created_at ASC, id ASC").Find(&assignments).Error
	return assignments, err
}

func (s *RDBConfigStore) ReplaceManualUserVirtualKeyAssignmentsAudited(ctx context.Context, userID string, virtualKeyIDs []string, assignedByUserID *string, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) error {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return ErrNotFound
	}
	ids := normalizeStringList(virtualKeyIDs)
	return s.ApplyAuditedChange(ctx, auditEvent, outboxEvent, func(tx *gorm.DB) error {
		var count int64
		if err := tx.Model(&tables.TableUser{}).Where("id = ?", userID).Count(&count).Error; err != nil {
			return err
		}
		if count == 0 {
			return ErrNotFound
		}
		if len(ids) > 0 {
			if err := tx.Model(&tables.TableVirtualKey{}).Where("id IN ?", ids).Count(&count).Error; err != nil {
				return err
			}
			if count != int64(len(ids)) {
				return ErrNotFound
			}
		}
		if err := tx.Model(&tables.TableUserVirtualKeyAssignment{}).Where("user_id = ? AND source = ? AND revoked_at IS NULL", userID, tables.UserVirtualKeySourceManual).Updates(map[string]any{"source": tables.UserVirtualKeySourceManual + "_revoked", "revoked_at": time.Now().UTC(), "updated_at": time.Now().UTC()}).Error; err != nil {
			return err
		}
		for _, virtualKeyID := range ids {
			assignment := &tables.TableUserVirtualKeyAssignment{ID: uuid.NewString(), UserID: userID, VirtualKeyID: virtualKeyID, Source: tables.UserVirtualKeySourceManual, AssignedByUserID: assignedByUserID}
			if err := tx.Create(assignment).Error; err != nil {
				if errors.Is(err, gorm.ErrDuplicatedKey) {
					return ErrAlreadyExists
				}
				return s.parseGormError(err)
			}
		}
		return nil
	})
}
