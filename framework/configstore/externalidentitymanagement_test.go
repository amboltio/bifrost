package configstore

import (
	"context"
	"testing"

	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRevokeExternalIdentityRequiresAnotherAuthenticationMethod(t *testing.T) {
	store := setupIdentityTestStore(t, ":memory:")
	ctx := context.Background()
	user := &tables.TableUser{Email: ptr("identity-only@example.test"), Status: tables.UserStatusActive}
	require.NoError(t, store.CreateUser(ctx, user))
	external := &tables.TableExternalIdentity{UserID: user.ID, ProviderID: "okta", Issuer: "https://okta.example.test", Subject: "subject", IsActive: true}
	require.NoError(t, store.CreateExternalIdentity(ctx, external))

	err := store.SetExternalIdentityActiveAudited(ctx, user.ID, external.ID, false,
		&tables.TableAuditEvent{ActorPrincipal: "user:admin", TargetType: "user", TargetID: &user.ID, Action: "identity.user.external_identity_revoked"},
		&tables.TableOutboxEvent{Topic: "identity.user.changed", DeduplicationKey: "identity.user:identity-only"},
	)
	require.ErrorIs(t, err, ErrLastAuthenticationMethod)

	got, err := store.GetExternalIdentityByIssuerSubject(ctx, external.Issuer, external.Subject)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.True(t, got.IsActive)
}

func TestRevokeExternalIdentityRevokesSessionsAndBumpsAuthVersion(t *testing.T) {
	store := setupIdentityTestStore(t, ":memory:")
	ctx := context.Background()
	user := &tables.TableUser{Email: ptr("identity-and-password@example.test"), Status: tables.UserStatusActive}
	require.NoError(t, store.CreateUser(ctx, user))
	require.NoError(t, store.CreateCredential(ctx, &tables.TableCredential{UserID: user.ID, Kind: tables.CredentialKindPassword, SecretHash: "argon2id$test", IsActive: true}))
	external := &tables.TableExternalIdentity{UserID: user.ID, ProviderID: "okta", Issuer: "https://okta.example.test", Subject: "subject", IsActive: true}
	require.NoError(t, store.CreateExternalIdentity(ctx, external))
	require.NoError(t, store.CreateSession(ctx, &tables.SessionsTable{Token: "session-token", UserID: &user.ID, AuthMethod: "oidc", AuthVersion: user.AuthVersion}))

	err := store.SetExternalIdentityActiveAudited(ctx, user.ID, external.ID, false,
		&tables.TableAuditEvent{ActorPrincipal: "user:admin", TargetType: "user", TargetID: &user.ID, Action: "identity.user.external_identity_revoked"},
		&tables.TableOutboxEvent{Topic: "identity.user.changed", DeduplicationKey: "identity.user:identity-password"},
	)
	require.NoError(t, err)
	updated, err := store.GetUser(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, uint64(2), updated.AuthVersion)
	var session tables.SessionsTable
	require.NoError(t, store.DB().First(&session).Error)
	assert.NotNil(t, session.RevokedAt)
}

func TestLinkExternalIdentityRejectsSubjectOwnedByAnotherUser(t *testing.T) {
	store := setupIdentityTestStore(t, ":memory:")
	ctx := context.Background()
	first := &tables.TableUser{Email: ptr("first-link@example.test"), Status: tables.UserStatusActive}
	second := &tables.TableUser{Email: ptr("second-link@example.test"), Status: tables.UserStatusActive}
	require.NoError(t, store.CreateUser(ctx, first))
	require.NoError(t, store.CreateUser(ctx, second))
	existing := &tables.TableExternalIdentity{UserID: first.ID, ProviderID: "okta", Issuer: "https://okta.example.test", Subject: "same-subject", IsActive: true}
	require.NoError(t, store.CreateExternalIdentity(ctx, existing))

	err := store.LinkExternalIdentity(ctx, second.ID, &tables.TableExternalIdentity{ProviderID: "okta", Issuer: existing.Issuer, Subject: existing.Subject, IsActive: true})
	require.ErrorIs(t, err, ErrAlreadyExists)
	got, err := store.GetExternalIdentityByIssuerSubject(ctx, existing.Issuer, existing.Subject)
	require.NoError(t, err)
	assert.Equal(t, first.ID, got.UserID)
}
