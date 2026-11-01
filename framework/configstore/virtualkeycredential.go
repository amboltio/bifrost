package configstore

import (
	"context"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"gorm.io/gorm"
)

// UpdateVirtualKeyCredential changes only credential columns. A concurrent
// rotation loses the hash compare-and-swap and rolls back its grant revocations;
// concurrent settings edits cannot be overwritten by the stale rotation snapshot.
func (s *RDBConfigStore) UpdateVirtualKeyCredential(ctx context.Context, key *tables.TableVirtualKey, expectedHash string, tx *gorm.DB) error {
	if tx == nil || key == nil || key.ID == "" {
		return ErrNotFound
	}
	var current tables.TableVirtualKey
	if err := dbForUpdate(tx.WithContext(ctx)).Select("id", "value_hash").Where("id = ?", key.ID).Take(&current).Error; err != nil {
		return s.parseGormError(err)
	}
	if current.ValueHash != expectedHash {
		return ErrNotFound
	}
	result := tx.WithContext(ctx).Where("id = ? AND value_hash = ?", key.ID, expectedHash).
		Select("value", "value_hash", "previous_value", "previous_value_hash", "previous_value_expires_at", "rotated_at", "encryption_status", "updated_at").Updates(key)
	if result.Error != nil {
		return s.parseGormError(result.Error)
	}
	if result.RowsAffected != 1 {
		return ErrNotFound
	}
	return nil
}
