package configstore

import (
	"context"
	"testing"

	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRDBProvisionOIDCIdentityCreatesViewerAndJournal(t *testing.T) {
	store := setupIdentityTestStore(t, ":memory:")
	ctx := context.Background()
	require.NoError(t, store.DB().Create(&tables.TableRole{
		ID: "viewer", Name: "viewer", DisplayName: "Viewer", IsSystem: true,
	}).Error)

	user, err := store.ProvisionOIDCIdentity(ctx,
		&tables.TableUser{Email: ptr("new.user@example.test"), DisplayName: "New User", EmailVerified: true},
		&tables.TableExternalIdentity{ProviderID: "entra", Issuer: "https://login.example.test", Subject: "subject-1", IsActive: true},
		"viewer",
	)
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.NotEmpty(t, user.ID)
	assert.Equal(t, tables.UserStatusActive, user.Status)

	assignments, err := store.GetUserRoleAssignments(ctx, user.ID)
	require.NoError(t, err)
	require.Len(t, assignments, 1)
	assert.Equal(t, "viewer", assignments[0].RoleID)

	external, err := store.GetExternalIdentityByIssuerSubject(ctx, "https://login.example.test", "subject-1")
	require.NoError(t, err)
	require.NotNil(t, external)
	assert.Equal(t, user.ID, external.UserID)

	var audits []tables.TableAuditEvent
	require.NoError(t, store.DB().Find(&audits).Error)
	require.Len(t, audits, 1)
	assert.Equal(t, "identity.user.created", audits[0].Action)
	assert.Equal(t, "anonymous:oidc", audits[0].ActorPrincipal)

	var outbox []tables.TableOutboxEvent
	require.NoError(t, store.DB().Find(&outbox).Error)
	require.Len(t, outbox, 1)
	assert.Equal(t, "identity.user.changed", outbox[0].Topic)
}

func TestRDBProvisionOIDCIdentityRejectsExistingEmail(t *testing.T) {
	store := setupIdentityTestStore(t, ":memory:")
	ctx := context.Background()
	require.NoError(t, store.DB().Create(&tables.TableRole{ID: "viewer", Name: "viewer", DisplayName: "Viewer"}).Error)
	require.NoError(t, store.CreateUser(ctx, &tables.TableUser{Email: ptr("existing@example.test")}))

	_, err := store.ProvisionOIDCIdentity(ctx,
		&tables.TableUser{Email: ptr("EXISTING@example.test"), DisplayName: "Collision", EmailVerified: true},
		&tables.TableExternalIdentity{ProviderID: "entra", Issuer: "https://login.example.test", Subject: "subject-2", IsActive: true},
		"viewer",
	)
	require.Error(t, err)

	var users []tables.TableUser
	require.NoError(t, store.DB().Find(&users).Error)
	assert.Len(t, users, 1)
	var externals []tables.TableExternalIdentity
	require.NoError(t, store.DB().Find(&externals).Error)
	assert.Empty(t, externals)
}
