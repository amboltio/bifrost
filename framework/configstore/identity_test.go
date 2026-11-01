package configstore

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupIdentityTestStore(t *testing.T, dsn string) *RDBConfigStore {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&tables.TableGovernanceConfig{},
		&tables.TableUser{},
		&tables.TableCredential{},
		&tables.TableExternalIdentity{},
		&tables.TableOIDCTransaction{},
		&tables.TableRole{},
		&tables.TableRoleAssignment{},
		&tables.SessionsTable{},
		&tables.TableAuditEvent{},
		&tables.TableOutboxEvent{},
		&tables.TableTeam{},
		&tables.TableUserTeamMembership{},
		&tables.TableBusinessUnit{},
		&tables.TableUserBusinessUnitMembership{},
		&tables.TableTeamBusinessUnitMembership{},
		&tables.TableAccessProfile{},
		&tables.TableUserAccessProfileAssignment{},
		&tables.TableRoleAccessProfileAssignment{},
		&tables.TableProject{},
		&tables.TableProjectMember{},
		&tables.TableUserVirtualKeyAssignment{},
	))
	require.NoError(t, db.Create(&tables.TableRole{
		ID: tables.RoleIDSuperAdmin, Name: tables.RoleNameSuperAdmin,
		DisplayName: "Super administrator", IsSystem: true, IsImmutable: true,
	}).Error)

	store := &RDBConfigStore{}
	store.db.Store(db)
	return store
}

func ptr(value string) *string { return &value }

func TestInitialAdminCreatesDurablePolicyAndCannotReopenSetup(t *testing.T) {
	store := setupIdentityTestStore(t, ":memory:")
	ctx := context.Background()
	user, err := store.CreateInitialSuperAdmin(ctx, &tables.TableUser{Email: ptr("admin@example.test"), Status: tables.UserStatusActive}, &tables.TableCredential{Kind: tables.CredentialKindPassword, SecretHash: "test-verifier", IsActive: true})
	require.NoError(t, err)
	state, err := store.GetDashboardIdentityState(ctx)
	require.NoError(t, err)
	require.True(t, state.Initialized)
	policy, err := store.GetAuthConfig(ctx)
	require.NoError(t, err)
	require.NotNil(t, policy)
	assert.Equal(t, []string{"local"}, policy.AuthenticationMethods())
	require.NoError(t, store.DB().Model(user).Update("status", tables.UserStatusDisabled).Error)
	_, err = store.CreateInitialSuperAdmin(ctx, &tables.TableUser{Email: ptr("attacker@example.test")}, nil)
	require.ErrorIs(t, err, ErrAlreadyExists)
}

// TestIdentityMigrationCreatesCanonicalTablesAndSuperAdminRole protects the
// migration boundary before authentication code starts depending on it. The
// initial super-admin role is a durable serialization row for the first-user
// bootstrap; it must be present on every fresh deployment.
func TestIdentityMigrationCreatesCanonicalTablesAndSuperAdminRole(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	require.NoError(t, err)

	require.NoError(t, triggerMigrations(context.Background(), db, testMigrationLogger))

	for _, table := range []string{
		"identity_users",
		"identity_credentials",
		"identity_external_identities",
		"identity_oidc_transactions",
		"identity_roles",
		"identity_role_assignments",
		"identity_user_team_memberships",
		"governance_business_units",
		"identity_user_business_unit_memberships",
		"identity_team_business_unit_memberships",
		"governance_access_profiles",
		"identity_user_access_profile_assignments",
		"governance_projects",
		"identity_project_members",
		"identity_user_virtual_key_assignments",
	} {
		var count int64
		require.NoError(t, db.Raw("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?", table).Scan(&count).Error)
		require.Equalf(t, int64(1), count, "expected canonical identity table %q", table)
	}

	var count int64
	require.NoError(t, db.Raw("SELECT COUNT(*) FROM identity_roles WHERE id = ? AND name = ?", "super_admin", "super_admin").Scan(&count).Error)
	require.Equal(t, int64(1), count)
}

func TestRDBIdentityStoreNormalizesEmailAndRejectsDuplicate(t *testing.T) {
	store := setupIdentityTestStore(t, ":memory:")
	ctx := context.Background()

	user := &tables.TableUser{Email: ptr(" Alice.Example@Example.test "), DisplayName: "Alice"}
	require.NoError(t, store.CreateUser(ctx, user))
	require.NotEmpty(t, user.ID)
	require.NotNil(t, user.NormalizedEmail)
	assert.Equal(t, "alice.example@example.test", *user.NormalizedEmail)
	assert.Equal(t, uint64(1), user.AuthVersion)

	found, err := store.GetUserByNormalizedEmail(ctx, "ALICE.EXAMPLE@example.TEST")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, user.ID, found.ID)
	assert.Equal(t, "Alice.Example@Example.test", *found.Email)

	err = store.CreateUser(ctx, &tables.TableUser{Email: ptr("alice.example@example.test")})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAlreadyExists)
}

func TestRDBIdentityStoreRetainsDisabledIdentityAndExternalBinding(t *testing.T) {
	store := setupIdentityTestStore(t, ":memory:")
	ctx := context.Background()

	user := &tables.TableUser{Email: ptr("alice@example.test")}
	otherUser := &tables.TableUser{Email: ptr("bob@example.test")}
	require.NoError(t, store.CreateUser(ctx, user))
	require.NoError(t, store.CreateUser(ctx, otherUser))

	external := &tables.TableExternalIdentity{
		UserID: user.ID, ProviderID: "google", Issuer: "https://accounts.google.com", Subject: "subject-1",
	}
	require.NoError(t, store.CreateExternalIdentity(ctx, external))
	err := store.CreateExternalIdentity(ctx, &tables.TableExternalIdentity{
		UserID: otherUser.ID, ProviderID: "google", Issuer: "https://accounts.google.com", Subject: "subject-1",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAlreadyExists)

	disabledAt := time.Date(2026, time.September, 17, 8, 0, 0, 0, time.UTC)
	require.NoError(t, store.DisableUser(ctx, user.ID, disabledAt))
	require.NoError(t, store.DisableUser(ctx, user.ID, disabledAt)) // idempotent; does not re-bump the version.

	gotUser, err := store.GetUser(ctx, user.ID)
	require.NoError(t, err)
	require.NotNil(t, gotUser)
	assert.Equal(t, tables.UserStatusDisabled, gotUser.Status)
	assert.Equal(t, uint64(2), gotUser.AuthVersion)
	require.NotNil(t, gotUser.DisabledAt)
	assert.Equal(t, disabledAt, gotUser.DisabledAt.UTC())

	gotExternal, err := store.GetExternalIdentityByIssuerSubject(ctx, "https://accounts.google.com", "subject-1")
	require.NoError(t, err)
	require.NotNil(t, gotExternal)
	assert.Equal(t, external.ID, gotExternal.ID)
	assert.Equal(t, user.ID, gotExternal.UserID)
}

func TestRDBIdentityStoreProfileDTOOmitsCredentials(t *testing.T) {
	store := setupIdentityTestStore(t, ":memory:")
	ctx := context.Background()
	user := &tables.TableUser{Email: ptr("profile@example.test"), DisplayName: "Profile"}
	require.NoError(t, store.CreateUser(ctx, user))
	require.NoError(t, store.CreateCredential(ctx, &tables.TableCredential{
		UserID: user.ID, Kind: tables.CredentialKindPassword, SecretHash: "argon2id$secret",
	}))

	body, err := json.Marshal(NewUserProfile(*user))
	require.NoError(t, err)
	assert.NotContains(t, string(body), "argon2id")
	assert.NotContains(t, string(body), "credential")
	assert.NotContains(t, string(body), "secret_hash")
}

func TestRDBIdentityStoreSerializesConcurrentClaims(t *testing.T) {
	// The shared-cache DSN and single connection make SQLite serialize writes in
	// the same way that PostgreSQL's unique indexes serialize concurrent inserts.
	// The callers still begin together, exercising the store's duplicate path.
	store := setupIdentityTestStore(t, "file:identity-race?mode=memory&cache=shared")
	sqlDB, err := store.DB().DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })

	ctx := context.Background()
	start := make(chan struct{})
	var group sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			errs <- store.CreateUser(ctx, &tables.TableUser{Email: ptr("race@example.test")})
		}()
	}
	close(start)
	group.Wait()
	close(errs)

	var succeeded, duplicate int
	for err := range errs {
		if err == nil {
			succeeded++
		} else if errors.Is(err, ErrAlreadyExists) {
			duplicate++
		} else {
			t.Fatalf("unexpected concurrent user creation error: %v", err)
		}
	}
	assert.Equal(t, 1, succeeded)
	assert.Equal(t, 1, duplicate)

	var users []tables.TableUser
	require.NoError(t, store.DB().Find(&users).Error)
	require.Len(t, users, 1)

	first := &tables.TableUser{Email: ptr("first@example.test")}
	second := &tables.TableUser{Email: ptr("second@example.test")}
	require.NoError(t, store.CreateUser(ctx, first))
	require.NoError(t, store.CreateUser(ctx, second))

	start = make(chan struct{})
	errs = make(chan error, 2)
	for _, userID := range []string{first.ID, second.ID} {
		group.Add(1)
		go func(id string) {
			defer group.Done()
			<-start
			errs <- store.CreateExternalIdentity(ctx, &tables.TableExternalIdentity{
				UserID: id, ProviderID: "okta", Issuer: "https://idp.example.test", Subject: "same-subject",
			})
		}(userID)
	}
	close(start)
	group.Wait()
	close(errs)

	succeeded, duplicate = 0, 0
	for err := range errs {
		if err == nil {
			succeeded++
		} else if errors.Is(err, ErrAlreadyExists) {
			duplicate++
		} else {
			t.Fatalf("unexpected concurrent external identity creation error: %v", err)
		}
	}
	assert.Equal(t, 1, succeeded)
	assert.Equal(t, 1, duplicate)
}

func TestRDBIdentityStoreInitialSuperAdminCanOnlyBeCreatedOnce(t *testing.T) {
	store := setupIdentityTestStore(t, ":memory:")
	ctx := context.Background()

	user, err := store.CreateInitialSuperAdmin(ctx, &tables.TableUser{Email: ptr("admin@example.test")}, &tables.TableCredential{
		Kind: tables.CredentialKindLegacyPassword, SecretHash: "$2a$legacy",
	})
	require.NoError(t, err)
	require.NotNil(t, user)

	assignments, err := store.GetUserRoleAssignments(ctx, user.ID)
	require.NoError(t, err)
	require.Len(t, assignments, 1)
	assert.Equal(t, tables.RoleIDSuperAdmin, assignments[0].RoleID)

	_, err = store.CreateInitialSuperAdmin(ctx, &tables.TableUser{Email: ptr("second@example.test")}, nil)
	require.ErrorIs(t, err, ErrAlreadyExists)
}

func TestCreateLocalSuperAdminPreservesPolicyAndRejectsDuplicates(t *testing.T) {
	store := setupIdentityTestStore(t, ":memory:")
	ctx := context.Background()
	initial := &AuthConfig{IsEnabled: true, LocalLogin: &LocalLoginConfig{IsEnabled: false, SessionTTLSeconds: 7200, IdleTimeoutSeconds: 600}, OIDCProviders: []OIDCProviderConfig{{ID: "company", DisplayName: "Company", IsEnabled: true, Type: "generic", IssuerURL: "https://id.example.test", ClientID: schemas.NewSecretVar("company-client"), ClientSecret: schemas.NewSecretVar("company-secret")}}}
	require.NoError(t, writeDashboardPolicy(store.DB(), initial, 7))
	create := func(email string) (*tables.TableUser, error) {
		return store.CreateLocalSuperAdmin(ctx, &tables.TableUser{Email: ptr(email), DisplayName: "Operator"}, &tables.TableCredential{Kind: tables.CredentialKindPassword, SecretHash: "$argon2id$test", IsActive: true}, nil)
	}
	first, err := create("Admin@Example.test")
	require.NoError(t, err)
	assert.Equal(t, tables.UserStatusActive, first.Status)
	second, err := create("recovery@example.test")
	require.NoError(t, err)
	require.NotEqual(t, first.ID, second.ID)
	_, err = create(" ADMIN@example.test ")
	require.ErrorIs(t, err, ErrAlreadyExists)
	policy, err := store.GetDashboardAuthPolicy(ctx)
	require.NoError(t, err)
	assert.Equal(t, uint64(9), policy.Revision)
	require.NotNil(t, policy.AuthConfig.LocalLogin)
	assert.True(t, policy.AuthConfig.LocalLogin.IsEnabled)
	assert.Equal(t, 7200, policy.AuthConfig.LocalLogin.SessionTTLSeconds)
	assert.Equal(t, 600, policy.AuthConfig.LocalLogin.IdleTimeoutSeconds)
	assert.Equal(t, initial.OIDCProviders, policy.AuthConfig.OIDCProviders)
	for _, model := range []any{&tables.TableUser{}, &tables.TableCredential{}, &tables.TableRoleAssignment{}, &tables.TableAuditEvent{}, &tables.TableOutboxEvent{}} {
		var count int64
		require.NoError(t, store.DB().Model(model).Count(&count).Error)
		assert.Equal(t, int64(2), count)
	}
	state, err := store.GetDashboardIdentityState(ctx)
	require.NoError(t, err)
	assert.True(t, state.Initialized)
}

func TestCreateLocalSuperAdminRollsBackOnAuditFailure(t *testing.T) {
	for _, table := range []string{"identity_audit_events", "identity_outbox_events", "governance_config"} {
		t.Run(table, func(t *testing.T) {
			store := setupIdentityTestStore(t, ":memory:")
			require.NoError(t, store.DB().Exec("CREATE TRIGGER reject_local_admin_write BEFORE INSERT ON "+table+" BEGIN SELECT RAISE(ABORT, 'write unavailable'); END").Error)
			_, err := store.CreateLocalSuperAdmin(context.Background(), &tables.TableUser{Email: ptr("admin@example.test")}, &tables.TableCredential{Kind: tables.CredentialKindPassword, SecretHash: "$argon2id$test", IsActive: true}, nil)
			require.Error(t, err)
			for _, model := range []any{&tables.TableUser{}, &tables.TableCredential{}, &tables.TableRoleAssignment{}, &tables.TableAuditEvent{}, &tables.TableOutboxEvent{}, &tables.TableGovernanceConfig{}} {
				var count int64
				require.NoError(t, store.DB().Model(model).Count(&count).Error)
				assert.Zero(t, count)
			}
		})
	}
}

func TestCreateLocalSuperAdminConcurrentDuplicate(t *testing.T) {
	store := setupIdentityTestStore(t, filepath.Join(t.TempDir(), "identity.db")+"?_txlock=immediate&_busy_timeout=10000")
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, email := range []string{"admin@example.test", "ADMIN@example.test"} {
		go func(email string) {
			<-start
			_, err := store.CreateLocalSuperAdmin(context.Background(), &tables.TableUser{Email: ptr(email)}, &tables.TableCredential{Kind: tables.CredentialKindPassword, SecretHash: "$argon2id$test", IsActive: true}, nil)
			results <- err
		}(email)
	}
	close(start)
	first, second := <-results, <-results
	if first == nil {
		require.ErrorIs(t, second, ErrAlreadyExists)
	} else {
		require.ErrorIs(t, first, ErrAlreadyExists)
		require.NoError(t, second)
	}
	for _, model := range []any{&tables.TableUser{}, &tables.TableCredential{}, &tables.TableRoleAssignment{}, &tables.TableAuditEvent{}, &tables.TableOutboxEvent{}} {
		var count int64
		require.NoError(t, store.DB().Model(model).Count(&count).Error)
		assert.Equal(t, int64(1), count)
	}
}
