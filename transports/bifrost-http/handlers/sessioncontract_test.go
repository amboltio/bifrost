package handlers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthStatusResponseAdvertisesImplementedIdentityFeatures(t *testing.T) {
	response := newAuthStatusResponse(true, false)

	assert.True(t, response.IsAuthEnabled)
	assert.False(t, response.HasValidToken)
	assert.Equal(t, "password", response.AuthType)
	assert.True(t, response.IdentityCapabilities.LocalUsers)
	assert.True(t, response.IdentityCapabilities.OIDCLogin)
	assert.True(t, response.IdentityCapabilities.Organizations)
	assert.True(t, response.IdentityCapabilities.Roles)
	assert.True(t, response.IdentityCapabilities.AccessProfiles)
	assert.True(t, response.IdentityCapabilities.Projects)
	assert.True(t, response.IdentityCapabilities.UserAnalytics)
	assert.Equal(t, "password", dashboardAuthTypeForMethods([]string{"local", "oidc"}))
	assert.Equal(t, "sso", dashboardAuthTypeForMethods([]string{"oidc"}))
	assert.Equal(t, "none", dashboardAuthTypeForMethods(nil))
}
