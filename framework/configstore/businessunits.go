package configstore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"gorm.io/gorm"
)

type BusinessUnitQueryParams struct {
	Search string
	Limit  int
	Offset int
}

// BusinessUnitManagementStore is the bounded persistence contract for the
// organization hierarchy. Membership methods preserve source ownership.
type BusinessUnitManagementStore interface {
	ListBusinessUnits(ctx context.Context, params BusinessUnitQueryParams) ([]tables.TableBusinessUnit, int64, error)
	GetBusinessUnit(ctx context.Context, id string) (*tables.TableBusinessUnit, error)
	CreateBusinessUnitAudited(ctx context.Context, unit *tables.TableBusinessUnit, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) (*tables.TableBusinessUnit, error)
	UpdateBusinessUnitAudited(ctx context.Context, id, name, description string, customerID *string, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) (*tables.TableBusinessUnit, error)
	DeleteBusinessUnitAudited(ctx context.Context, id string, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) error
	ListUserBusinessUnitMemberships(ctx context.Context, userID string) ([]tables.TableUserBusinessUnitMembership, error)
	ReplaceManualUserBusinessUnitMembershipsAudited(ctx context.Context, userID string, businessUnitIDs []string, assignedByUserID *string, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) error
}

func (s *RDBConfigStore) ListBusinessUnits(ctx context.Context, params BusinessUnitQueryParams) ([]tables.TableBusinessUnit, int64, error) {
	limit := params.Limit
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	query := s.DB().WithContext(ctx).Model(&tables.TableBusinessUnit{})
	if search := strings.TrimSpace(params.Search); search != "" {
		needle := "%" + strings.ToLower(search) + "%"
		query = query.Where("LOWER(name) LIKE ? OR LOWER(description) LIKE ?", needle, needle)
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var units []tables.TableBusinessUnit
	if err := query.Order("name ASC, id ASC").Limit(limit).Offset(max(params.Offset, 0)).Find(&units).Error; err != nil {
		return nil, 0, err
	}
	return units, total, nil
}

func (s *RDBConfigStore) GetBusinessUnit(ctx context.Context, id string) (*tables.TableBusinessUnit, error) {
	var unit tables.TableBusinessUnit
	if err := s.DB().WithContext(ctx).First(&unit, "id = ?", strings.TrimSpace(id)).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &unit, nil
}

func (s *RDBConfigStore) CreateBusinessUnitAudited(ctx context.Context, unit *tables.TableBusinessUnit, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) (*tables.TableBusinessUnit, error) {
	if unit == nil {
		return nil, fmt.Errorf("business unit is required")
	}
	unit.ID = strings.TrimSpace(unit.ID)
	if unit.ID == "" {
		unit.ID = uuid.NewString()
	}
	unit.Name = strings.TrimSpace(unit.Name)
	unit.Description = strings.TrimSpace(unit.Description)
	if unit.Name == "" {
		return nil, fmt.Errorf("business unit name is required")
	}
	err := s.ApplyAuditedChange(ctx, auditEvent, outboxEvent, func(tx *gorm.DB) error {
		if unit.CustomerID != nil {
			var count int64
			if err := tx.Model(&tables.TableCustomer{}).Where("id = ?", strings.TrimSpace(*unit.CustomerID)).Count(&count).Error; err != nil {
				return err
			}
			if count == 0 {
				return ErrNotFound
			}
		}
		if err := tx.WithContext(ctx).Create(unit).Error; err != nil {
			return s.parseGormError(err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return unit, nil
}

func (s *RDBConfigStore) UpdateBusinessUnitAudited(ctx context.Context, id, name, description string, customerID *string, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) (*tables.TableBusinessUnit, error) {
	id, name, description = strings.TrimSpace(id), strings.TrimSpace(name), strings.TrimSpace(description)
	if id == "" || name == "" {
		return nil, ErrNotFound
	}
	var unit tables.TableBusinessUnit
	err := s.ApplyAuditedChange(ctx, auditEvent, outboxEvent, func(tx *gorm.DB) error {
		if err := dbForUpdate(tx).First(&unit, "id = ?", id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		if customerID != nil {
			var count int64
			if err := tx.Model(&tables.TableCustomer{}).Where("id = ?", strings.TrimSpace(*customerID)).Count(&count).Error; err != nil {
				return err
			}
			if count == 0 {
				return ErrNotFound
			}
		}
		if err := tx.WithContext(ctx).Model(&tables.TableBusinessUnit{}).Where("id = ?", id).Updates(map[string]any{"name": name, "description": description, "customer_id": customerID, "updated_at": time.Now().UTC()}).Error; err != nil {
			return s.parseGormError(err)
		}
		unit.Name, unit.Description, unit.CustomerID = name, description, customerID
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &unit, nil
}

func (s *RDBConfigStore) DeleteBusinessUnitAudited(ctx context.Context, id string, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return ErrNotFound
	}
	return s.ApplyAuditedChange(ctx, auditEvent, outboxEvent, func(tx *gorm.DB) error {
		var unit tables.TableBusinessUnit
		if err := dbForUpdate(tx).First(&unit, "id = ?", id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		for _, model := range []any{&tables.TableUserBusinessUnitMembership{}, &tables.TableTeamBusinessUnitMembership{}} {
			var count int64
			if err := tx.Model(model).Where("business_unit_id = ?", id).Count(&count).Error; err != nil {
				return err
			}
			if count > 0 {
				return ErrBusinessUnitInUse
			}
		}
		return tx.Delete(&unit).Error
	})
}

func (s *RDBConfigStore) ListUserBusinessUnitMemberships(ctx context.Context, userID string) ([]tables.TableUserBusinessUnitMembership, error) {
	var memberships []tables.TableUserBusinessUnitMembership
	err := s.DB().WithContext(ctx).Where("user_id = ?", strings.TrimSpace(userID)).Order("created_at ASC, id ASC").Find(&memberships).Error
	return memberships, err
}

func (s *RDBConfigStore) ReplaceManualUserBusinessUnitMembershipsAudited(ctx context.Context, userID string, businessUnitIDs []string, assignedByUserID *string, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) error {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return ErrNotFound
	}
	ids := normalizedStringIDs(businessUnitIDs)
	return s.ApplyAuditedChange(ctx, auditEvent, outboxEvent, func(tx *gorm.DB) error {
		var userCount int64
		if err := tx.Model(&tables.TableUser{}).Where("id = ?", userID).Count(&userCount).Error; err != nil {
			return err
		}
		if userCount == 0 {
			return ErrNotFound
		}
		if len(ids) > 0 {
			var unitCount int64
			if err := tx.Model(&tables.TableBusinessUnit{}).Where("id IN ?", ids).Count(&unitCount).Error; err != nil {
				return err
			}
			if unitCount != int64(len(ids)) {
				return ErrNotFound
			}
		}
		if err := tx.Where("user_id = ? AND source = ?", userID, tables.BusinessUnitSourceManual).Delete(&tables.TableUserBusinessUnitMembership{}).Error; err != nil {
			return err
		}
		for _, businessUnitID := range ids {
			membership := &tables.TableUserBusinessUnitMembership{ID: uuid.NewString(), UserID: userID, BusinessUnitID: businessUnitID, Source: tables.BusinessUnitSourceManual, AssignedByUserID: assignedByUserID}
			if err := tx.Create(membership).Error; err != nil {
				return s.parseGormError(err)
			}
		}
		return nil
	})
}
