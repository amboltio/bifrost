package identity

import (
	"context"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/configstore"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type bootstrapStoreStub struct {
	authConfig *configstore.AuthConfig
	result     *configstore.LegacyAdminBootstrapResult
	input      *configstore.LegacyAdminBootstrapInput
}

func (s *bootstrapStoreStub) GetAuthConfig(context.Context) (*configstore.AuthConfig, error) {
	return s.authConfig, nil
}

func (s *bootstrapStoreStub) BootstrapLegacyAdmin(_ context.Context, input configstore.LegacyAdminBootstrapInput) (*configstore.LegacyAdminBootstrapResult, error) {
	s.input = &input
	return s.result, nil
}

func TestBootstrapLegacyAdminLeavesEmptyDeploymentInSetupMode(t *testing.T) {
	result, err := BootstrapLegacyAdmin(context.Background(), &bootstrapStoreStub{})
	require.NoError(t, err)
	assert.True(t, result.NeedsSetup)
	assert.False(t, result.Imported)
}

func TestBootstrapLegacyAdminUsesResolvedLegacyConfiguration(t *testing.T) {
	store := &bootstrapStoreStub{
		authConfig: &configstore.AuthConfig{
			AdminUserName: schemas.NewSecretVar("admin@example.test"),
			AdminPassword: schemas.NewSecretVar("$2a$10$legacy-bcrypt"),
		},
		result: &configstore.LegacyAdminBootstrapResult{Imported: true, User: &tables.TableUser{ID: "user-1"}},
	}
	result, err := BootstrapLegacyAdmin(context.Background(), store)
	require.NoError(t, err)
	assert.True(t, result.Imported)
	assert.Equal(t, "user-1", result.UserID)
	require.NotNil(t, store.input)
	assert.Equal(t, "admin@example.test", store.input.Username)
	assert.Equal(t, "$2a$10$legacy-bcrypt", store.input.PasswordHash)
}
