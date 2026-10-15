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

// RecoveryTokenStore is the narrow persistence contract used by the password
// recovery service. Redemption makes the token, credential, user version, and
// active sessions transition in one transaction.
type RecoveryTokenStore interface {
	CreateRecoveryToken(ctx context.Context, token *tables.TableRecoveryToken, tx ...*gorm.DB) error
	RedeemRecoveryToken(ctx context.Context, tokenDigest, passwordHash string, now time.Time) (*tables.TableRecoveryToken, error)
}

// AuditedRecoveryTokenStore keeps an administrator-issued recovery token and
// its security evidence in the same transaction.
type AuditedRecoveryTokenStore interface {
	RecoveryTokenStore
	CreateRecoveryTokenAudited(ctx context.Context, token *tables.TableRecoveryToken, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) error
}

// CreateRecoveryToken persists a digest-only one-time credential.
func (s *RDBConfigStore) CreateRecoveryToken(ctx context.Context, token *tables.TableRecoveryToken, tx ...*gorm.DB) error {
	if token == nil || strings.TrimSpace(token.UserID) == "" || !isRecoveryPurpose(token.Purpose) || len(token.TokenDigest) != 64 || token.ExpiresAt.IsZero() {
		return fmt.Errorf("recovery token user ID, purpose, SHA-256 digest, and expiry are required")
	}
	if token.ID == "" {
		token.ID = uuid.NewString()
	}
	token.Purpose = strings.TrimSpace(token.Purpose)
	token.ExpiresAt = token.ExpiresAt.UTC()
	if err := s.identityDB(tx).WithContext(ctx).Create(token).Error; err != nil {
		return s.parseGormError(err)
	}
	return nil
}

// CreateRecoveryTokenAudited persists only a token digest together with the
// operator action that issued it. The plaintext token never crosses this
// storage boundary.
func (s *RDBConfigStore) CreateRecoveryTokenAudited(ctx context.Context, token *tables.TableRecoveryToken, auditEvent *tables.TableAuditEvent, outboxEvent *tables.TableOutboxEvent) error {
	return s.ApplyAuditedChange(ctx, auditEvent, outboxEvent, func(tx *gorm.DB) error {
		return s.CreateRecoveryToken(ctx, token, tx)
	})
}

// RedeemRecoveryToken burns a valid token and installs a new current password
// verifier. Old legacy bcrypt verifiers are disabled and every user session is
// revoked before commit, so a successful reset cannot leave an old session
// usable on another device.
func (s *RDBConfigStore) RedeemRecoveryToken(ctx context.Context, tokenDigest, passwordHash string, now time.Time) (*tables.TableRecoveryToken, error) {
	if len(tokenDigest) != 64 || strings.TrimSpace(passwordHash) == "" {
		return nil, ErrNotFound
	}
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var redeemed tables.TableRecoveryToken
	err := s.DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		query := dbForUpdate(tx).Where("token_digest = ? AND consumed_at IS NULL AND expires_at > ?", tokenDigest, now)
		if err := query.First(&redeemed).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		if result := tx.Model(&tables.TableRecoveryToken{}).Where("id = ? AND consumed_at IS NULL", redeemed.ID).Update("consumed_at", now); result.Error != nil {
			return result.Error
		} else if result.RowsAffected != 1 {
			return ErrNotFound
		}
		if result := tx.Model(&tables.TableUser{}).Where("id = ?", redeemed.UserID).Update("auth_version", gorm.Expr("auth_version + ?", 1)); result.Error != nil {
			return result.Error
		} else if result.RowsAffected != 1 {
			return ErrNotFound
		}
		var user tables.TableUser
		if err := tx.First(&user, "id = ?", redeemed.UserID).Error; err != nil {
			return err
		}

		var current tables.TableCredential
		err := tx.Where("user_id = ? AND kind = ?", redeemed.UserID, tables.CredentialKindPassword).First(&current).Error
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			if err := tx.Create(&tables.TableCredential{
				ID: uuid.NewString(), UserID: redeemed.UserID, Kind: tables.CredentialKindPassword,
				SecretHash: passwordHash, Version: 1, IsActive: true,
			}).Error; err != nil {
				return s.parseGormError(err)
			}
		case err != nil:
			return err
		default:
			if err := tx.Model(&current).Updates(map[string]any{
				"secret_hash": passwordHash, "is_active": true, "version": gorm.Expr("version + ?", 1),
			}).Error; err != nil {
				return err
			}
		}
		if err := tx.Model(&tables.TableCredential{}).
			Where("user_id = ? AND kind = ?", redeemed.UserID, tables.CredentialKindLegacyPassword).
			Update("is_active", false).Error; err != nil {
			return err
		}
		if err := tx.Model(&tables.SessionsTable{}).
			Where("user_id = ? AND revoked_at IS NULL", redeemed.UserID).
			Update("revoked_at", now).Error; err != nil {
			return err
		}
		redeemed.ConsumedAt = &now
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &redeemed, nil
}

func isRecoveryPurpose(value string) bool {
	switch strings.TrimSpace(value) {
	case tables.RecoveryTokenPurposeEnrollment, tables.RecoveryTokenPurposeReset:
		return true
	default:
		return false
	}
}
