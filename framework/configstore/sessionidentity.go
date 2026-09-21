package configstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	// SessionAuthMethodLegacy identifies a token created before the canonical
	// identity service. New methods are introduced by the session service.
	SessionAuthMethodLegacy = "legacy"
)

var (
	// ErrLegacyBootstrapAmbiguous stops startup when a database contains
	// canonical identities but no durable import marker. Guessing which user
	// owns the old global admin credential would be a privilege escalation.
	ErrLegacyBootstrapAmbiguous = errors.New("legacy admin bootstrap is ambiguous")
)

// LegacyAdminBootstrapInput is the trusted, resolved legacy credential passed
// by framework/identity. PasswordHash must be the configured bcrypt string;
// this store copies it verbatim and never logs it.
type LegacyAdminBootstrapInput struct {
	Username     string
	PasswordHash string
	Now          time.Time
}

// LegacyAdminBootstrapResult describes an idempotent migration without
// exposing a verifier. A false Imported value means an earlier process wrote
// the marker and this invocation loaded its canonical user.
type LegacyAdminBootstrapResult struct {
	User            *tables.TableUser
	Imported        bool
	BoundSessions   int64
	RevokedSessions int64
}

// LegacyAdminBootstrapStore is the deliberately small service-facing
// contract. It avoids expanding the broad ConfigStore interface solely for a
// startup concern while still allowing the HTTP server to type-check the
// concrete persistent store before running bootstrap.
type LegacyAdminBootstrapStore interface {
	GetAuthConfig(ctx context.Context) (*AuthConfig, error)
	BootstrapLegacyAdmin(ctx context.Context, input LegacyAdminBootstrapInput) (*LegacyAdminBootstrapResult, error)
}

type legacyBootstrapMarker struct {
	UserID     string    `json:"user_id"`
	ImportedAt time.Time `json:"imported_at"`
}

// BootstrapLegacyAdmin atomically imports the pre-identity dashboard admin,
// grants its immutable role, binds its old globally-owned sessions, and writes
// a marker. The role row is locked to serialize competing replicas.
func (s *RDBConfigStore) BootstrapLegacyAdmin(ctx context.Context, input LegacyAdminBootstrapInput) (*LegacyAdminBootstrapResult, error) {
	username := strings.TrimSpace(input.Username)
	if username == "" {
		return nil, fmt.Errorf("legacy admin username is required")
	}
	if strings.TrimSpace(input.PasswordHash) == "" {
		return nil, fmt.Errorf("legacy admin bcrypt hash is required")
	}
	if _, err := bcrypt.Cost([]byte(input.PasswordHash)); err != nil {
		return nil, fmt.Errorf("legacy admin bcrypt hash is invalid: %w", err)
	}
	now := input.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}

	result := &LegacyAdminBootstrapResult{}
	err := s.DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var markerRow tables.TableGovernanceConfig
		err := dbForUpdate(tx).First(&markerRow, "key = ?", tables.ConfigIdentityLegacyBootstrapKey).Error
		if err == nil {
			return s.loadLegacyBootstrapMarker(ctx, tx, markerRow, now, result)
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}

		var role tables.TableRole
		if err := dbForUpdate(tx).First(&role, "id = ?", tables.RoleIDSuperAdmin).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("legacy admin bootstrap requires the seeded super-admin role")
			}
			return err
		}

		var userCount int64
		if err := tx.Model(&tables.TableUser{}).Count(&userCount).Error; err != nil {
			return err
		}
		if userCount != 0 {
			return fmt.Errorf("%w: found %d canonical user records without %s", ErrLegacyBootstrapAmbiguous, userCount, tables.ConfigIdentityLegacyBootstrapKey)
		}

		user := legacyBootstrapUser(username)
		user.ID = uuid.NewString()
		if err := tx.Create(user).Error; err != nil {
			return s.parseGormError(err)
		}
		credential := &tables.TableCredential{
			ID: uuid.NewString(), UserID: user.ID, Kind: tables.CredentialKindLegacyPassword,
			SecretHash: input.PasswordHash, Version: 1, IsActive: true,
		}
		if err := tx.Create(credential).Error; err != nil {
			return s.parseGormError(err)
		}
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&tables.TableRoleAssignment{
			ID: uuid.NewString(), UserID: user.ID, RoleID: role.ID,
		}).Error; err != nil {
			return s.parseGormError(err)
		}
		bound, err := bindUnownedLegacySessions(tx, user.ID, user.AuthVersion)
		if err != nil {
			return err
		}
		marker, err := json.Marshal(legacyBootstrapMarker{UserID: user.ID, ImportedAt: now})
		if err != nil {
			return fmt.Errorf("encode legacy bootstrap marker: %w", err)
		}
		if err := tx.Create(&tables.TableGovernanceConfig{
			Key: tables.ConfigIdentityLegacyBootstrapKey, Value: string(marker),
		}).Error; err != nil {
			return s.parseGormError(err)
		}
		result.User = user
		result.Imported = true
		result.BoundSessions = bound
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *RDBConfigStore) loadLegacyBootstrapMarker(ctx context.Context, tx *gorm.DB, row tables.TableGovernanceConfig, now time.Time, result *LegacyAdminBootstrapResult) error {
	var marker legacyBootstrapMarker
	if err := json.Unmarshal([]byte(row.Value), &marker); err != nil || marker.UserID == "" {
		if err == nil {
			err = errors.New("marker user ID is empty")
		}
		return fmt.Errorf("%w: legacy bootstrap marker is invalid: %v", ErrLegacyBootstrapAmbiguous, err)
	}
	var user tables.TableUser
	if err := dbForUpdate(tx).First(&user, "id = ?", marker.UserID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("%w: marker references missing user", ErrLegacyBootstrapAmbiguous)
		}
		return err
	}
	// Any ownerless session that appears after the marker cannot safely be
	// attributed. Revoke it durably and force a fresh login instead.
	revoked, err := revokeUnownedLegacySessions(tx, now)
	if err != nil {
		return err
	}
	result.User = &user
	result.RevokedSessions = revoked
	return nil
}

func legacyBootstrapUser(username string) *tables.TableUser {
	user := &tables.TableUser{DisplayName: username, Status: tables.UserStatusActive, AuthVersion: 1}
	if isLegacyEmail(username) {
		user.Email = &username
		return user
	}
	user.LegacyUsername = &username
	return user
}

func isLegacyEmail(value string) bool {
	address, err := mail.ParseAddress(value)
	return err == nil && address.Address == value && strings.Contains(value, "@")
}

func bindUnownedLegacySessions(tx *gorm.DB, userID string, authVersion uint64) (int64, error) {
	result := tx.Model(&tables.SessionsTable{}).
		Where("user_id IS NULL AND revoked_at IS NULL").
		Updates(map[string]any{
			"user_id": userID, "auth_method": SessionAuthMethodLegacy, "auth_version": authVersion,
		})
	return result.RowsAffected, result.Error
}

func revokeUnownedLegacySessions(tx *gorm.DB, now time.Time) (int64, error) {
	result := tx.Model(&tables.SessionsTable{}).
		Where("user_id IS NULL AND revoked_at IS NULL").
		Updates(map[string]any{"revoked_at": now, "auth_method": SessionAuthMethodLegacy})
	return result.RowsAffected, result.Error
}

// TouchIdentitySession advances the idle deadline only for an unrevoked
// session. A stale concurrent request cannot resurrect a session after logout.
func (s *RDBConfigStore) TouchIdentitySession(ctx context.Context, id int, lastSeenAt, idleExpiresAt time.Time) error {
	result := s.DB().WithContext(ctx).Model(&tables.SessionsTable{}).
		Where("id = ? AND revoked_at IS NULL", id).
		Updates(map[string]any{"last_seen_at": lastSeenAt.UTC(), "idle_expires_at": idleExpiresAt.UTC()})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return ErrNotFound
	}
	return nil
}

// RevokeIdentitySession marks one identity session unusable. It is idempotent
// so concurrent logout and auth-version invalidation produce the same state.
func (s *RDBConfigStore) RevokeIdentitySession(ctx context.Context, id int, revokedAt time.Time) error {
	result := s.DB().WithContext(ctx).Model(&tables.SessionsTable{}).
		Where("id = ? AND revoked_at IS NULL", id).
		Update("revoked_at", revokedAt.UTC())
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		var session tables.SessionsTable
		if err := s.DB().WithContext(ctx).First(&session, "id = ?", id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
	}
	return nil
}

// RevokeUserIdentitySession marks one active session revoked only when the
// supplied user owns it. It intentionally returns ErrNotFound for a missing,
// already-revoked, or another user's row so a self-service endpoint cannot
// enumerate session IDs.
func (s *RDBConfigStore) RevokeUserIdentitySession(ctx context.Context, userID string, id int, revokedAt time.Time) error {
	if strings.TrimSpace(userID) == "" || id <= 0 {
		return ErrNotFound
	}
	if revokedAt.IsZero() {
		revokedAt = time.Now().UTC()
	}
	result := s.DB().WithContext(ctx).Model(&tables.SessionsTable{}).
		Where("id = ? AND user_id = ? AND revoked_at IS NULL", id, userID).
		Update("revoked_at", revokedAt.UTC())
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return ErrNotFound
	}
	return nil
}

// ListUserIdentitySessions returns a user's session metadata in newest-first
// order. The query excludes Token and TokenHash at the database boundary so a
// future handler cannot accidentally serialize a reusable bearer credential.
func (s *RDBConfigStore) ListUserIdentitySessions(ctx context.Context, userID string) ([]tables.SessionsTable, error) {
	if strings.TrimSpace(userID) == "" {
		return []tables.SessionsTable{}, nil
	}
	var sessions []tables.SessionsTable
	err := s.DB().WithContext(ctx).Model(&tables.SessionsTable{}).
		Select("id", "expires_at", "user_id", "auth_method", "provider_id", "last_seen_at", "absolute_expires_at", "idle_expires_at", "revoked_at", "auth_version", "created_at", "updated_at").
		Where("user_id = ?", userID).
		Order("created_at DESC, id DESC").
		Find(&sessions).Error
	if err != nil {
		return nil, err
	}
	return sessions, nil
}

// RevokeUserIdentitySessions invalidates all active rows owned by a canonical
// user. It neither deletes session history nor touches another user's rows.
func (s *RDBConfigStore) RevokeUserIdentitySessions(ctx context.Context, userID string, revokedAt time.Time) (int64, error) {
	if strings.TrimSpace(userID) == "" {
		return 0, ErrNotFound
	}
	if revokedAt.IsZero() {
		revokedAt = time.Now().UTC()
	}
	result := s.DB().WithContext(ctx).Model(&tables.SessionsTable{}).
		Where("user_id = ? AND revoked_at IS NULL", userID).
		Update("revoked_at", revokedAt.UTC())
	if result.Error != nil {
		return 0, result.Error
	}
	return result.RowsAffected, nil
}
