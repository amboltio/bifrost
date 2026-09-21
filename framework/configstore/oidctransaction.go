package configstore

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"gorm.io/gorm"
)

// OIDCTransactionStore is the narrow persistence contract needed by the OIDC
// login service. A database transaction row allows callback processing to
// survive process restarts and makes state single-use across every replica.
type OIDCTransactionStore interface {
	CreateOIDCTransaction(ctx context.Context, transaction *tables.TableOIDCTransaction) error
	ClaimOIDCTransaction(ctx context.Context, stateHash string, now time.Time) (*tables.TableOIDCTransaction, error)
	DeleteExpiredOIDCTransactions(ctx context.Context, now time.Time) (int64, error)
}

func (s *RDBConfigStore) CreateOIDCTransaction(ctx context.Context, transaction *tables.TableOIDCTransaction) error {
	if transaction == nil {
		return fmt.Errorf("OIDC transaction cannot be nil")
	}
	if transaction.ID == "" {
		transaction.ID = uuid.NewString()
	}
	if err := s.DB().WithContext(ctx).Create(transaction).Error; err != nil {
		return s.parseGormError(err)
	}
	return nil
}

// ClaimOIDCTransaction atomically consumes an unexpired state. A callback
// which arrives twice, is expired, or is unknown returns nil without leaking
// which condition occurred to the browser.
func (s *RDBConfigStore) ClaimOIDCTransaction(ctx context.Context, stateHash string, now time.Time) (*tables.TableOIDCTransaction, error) {
	stateHash = strings.TrimSpace(stateHash)
	if stateHash == "" {
		return nil, nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}

	var transaction tables.TableOIDCTransaction
	err := s.DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&tables.TableOIDCTransaction{}).
			Where("state_hash = ? AND consumed_at IS NULL AND expires_at > ?", stateHash, now).
			Update("consumed_at", now)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return nil
		}
		return tx.Where("state_hash = ? AND consumed_at = ?", stateHash, now).First(&transaction).Error
	})
	if err != nil {
		return nil, err
	}
	if transaction.ID == "" {
		return nil, nil
	}
	return &transaction, nil
}

func (s *RDBConfigStore) DeleteExpiredOIDCTransactions(ctx context.Context, now time.Time) (int64, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	result := s.DB().WithContext(ctx).Where("expires_at <= ?", now.UTC()).Delete(&tables.TableOIDCTransaction{})
	if result.Error != nil {
		return 0, result.Error
	}
	return result.RowsAffected, nil
}
