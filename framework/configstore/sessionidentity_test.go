package configstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupLegacyBootstrapStore(t *testing.T) *RDBConfigStore {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&tables.TableGovernanceConfig{},
		&tables.TableUser{},
		&tables.TableCredential{},
		&tables.TableRole{},
		&tables.TableRoleAssignment{},
		&tables.SessionsTable{},
	))
	require.NoError(t, db.Create(&tables.TableRole{
		ID: tables.RoleIDSuperAdmin, Name: tables.RoleNameSuperAdmin,
		DisplayName: "Super administrator", IsSystem: true, IsImmutable: true,
	}).Error)
	store := &RDBConfigStore{}
	store.db.Store(db)
	return store
}

func TestIdentitySessionMigrationAddsOwnershipAndExpiryColumns(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE sessions (
		id integer primary key autoincrement,
		token text not null unique,
		expires_at datetime not null,
		created_at datetime not null,
		updated_at datetime not null,
		encryption_status varchar(20),
		token_hash varchar(64)
	)`).Error)

	require.NoError(t, migrationAddIdentitySessionFields(context.Background(), db, testMigrationLogger))
	for _, column := range []string{
		"user_id", "auth_method", "provider_id", "last_seen_at",
		"absolute_expires_at", "idle_expires_at", "revoked_at", "auth_version",
	} {
		assert.Truef(t, db.Migrator().HasColumn(&tables.SessionsTable{}, column), "expected sessions.%s", column)
	}
}

func TestRDBLegacyAdminBootstrapImportsHashAndBindsSessionsOnce(t *testing.T) {
	store := setupLegacyBootstrapStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.September, 17, 12, 0, 0, 0, time.UTC)
	legacyHash, err := bcrypt.GenerateFromPassword([]byte("legacy-password"), bcrypt.MinCost)
	require.NoError(t, err)
	require.NoError(t, store.CreateSession(ctx, &tables.SessionsTable{
		Token: "legacy-session", ExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
	}))

	first, err := store.BootstrapLegacyAdmin(ctx, LegacyAdminBootstrapInput{
		Username: "legacy-admin", PasswordHash: string(legacyHash), Now: now,
	})
	require.NoError(t, err)
	require.True(t, first.Imported)
	require.NotNil(t, first.User)
	assert.Nil(t, first.User.Email)
	require.NotNil(t, first.User.LegacyUsername)
	assert.Equal(t, "legacy-admin", *first.User.LegacyUsername)
	assert.Equal(t, int64(1), first.BoundSessions)

	credential, err := store.GetCredentialByUserIDAndKind(ctx, first.User.ID, tables.CredentialKindLegacyPassword)
	require.NoError(t, err)
	require.NotNil(t, credential)
	assert.Equal(t, string(legacyHash), credential.SecretHash)

	second, err := store.BootstrapLegacyAdmin(ctx, LegacyAdminBootstrapInput{
		Username: "legacy-admin", PasswordHash: string(legacyHash), Now: now.Add(time.Minute),
	})
	require.NoError(t, err)
	assert.False(t, second.Imported)
	require.NotNil(t, second.User)
	assert.Equal(t, first.User.ID, second.User.ID)

	session, err := store.GetSession(ctx, "legacy-session")
	require.NoError(t, err)
	require.NotNil(t, session)
	require.NotNil(t, session.UserID)
	assert.Equal(t, first.User.ID, *session.UserID)
	assert.Equal(t, SessionAuthMethodLegacy, session.AuthMethod)
	assert.Equal(t, first.User.AuthVersion, session.AuthVersion)

	var users, credentials, markers int64
	require.NoError(t, store.DB().Model(&tables.TableUser{}).Count(&users).Error)
	require.NoError(t, store.DB().Model(&tables.TableCredential{}).Count(&credentials).Error)
	require.NoError(t, store.DB().Model(&tables.TableGovernanceConfig{}).Where("key = ?", tables.ConfigIdentityLegacyBootstrapKey).Count(&markers).Error)
	assert.Equal(t, int64(1), users)
	assert.Equal(t, int64(1), credentials)
	assert.Equal(t, int64(1), markers)

	// A session without a canonical owner appearing after the marker cannot be
	// attributed safely. A repeat bootstrap revokes it rather than extending
	// legacy-admin access to an unknown principal.
	require.NoError(t, store.CreateSession(ctx, &tables.SessionsTable{
		Token: "unexpected-unowned-session", ExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
	}))
	third, err := store.BootstrapLegacyAdmin(ctx, LegacyAdminBootstrapInput{
		Username: "legacy-admin", PasswordHash: string(legacyHash), Now: now.Add(2 * time.Minute),
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), third.RevokedSessions)
	unexpected, err := store.GetSession(ctx, "unexpected-unowned-session")
	require.NoError(t, err)
	require.NotNil(t, unexpected)
	assert.False(t, unexpected.IsActiveAt(now.Add(2*time.Minute)))
}

func TestRDBLegacyAdminBootstrapRejectsAmbiguousExistingIdentity(t *testing.T) {
	store := setupLegacyBootstrapStore(t)
	ctx := context.Background()
	require.NoError(t, store.CreateUser(ctx, &tables.TableUser{Email: ptr("existing@example.test")}))
	legacyHash, err := bcrypt.GenerateFromPassword([]byte("legacy-password"), bcrypt.MinCost)
	require.NoError(t, err)

	result, err := store.BootstrapLegacyAdmin(ctx, LegacyAdminBootstrapInput{
		Username: "legacy-admin", PasswordHash: string(legacyHash), Now: time.Now().UTC(),
	})
	assert.Nil(t, result)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrLegacyBootstrapAmbiguous))
}

func TestIdentitySessionActivityHonorsLegacyAndIdentityExpiries(t *testing.T) {
	now := time.Date(2026, time.September, 17, 12, 0, 0, 0, time.UTC)
	session := tables.SessionsTable{ExpiresAt: now.Add(time.Hour)}
	assert.True(t, session.IsActiveAt(now))

	idleExpired := now.Add(-time.Second)
	session.IdleExpiresAt = &idleExpired
	assert.False(t, session.IsActiveAt(now))

	stillValid := now.Add(time.Hour)
	session.IdleExpiresAt = &stillValid
	session.AbsoluteExpiresAt = &stillValid
	revokedAt := now
	session.RevokedAt = &revokedAt
	assert.False(t, session.IsActiveAt(now))
}
