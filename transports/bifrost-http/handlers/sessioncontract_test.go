package handlers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthStatusResponseDoesNotAdvertiseIncompleteIdentityFeatures(t *testing.T) {
	response := newAuthStatusResponse(true, false)

	assert.True(t, response.IsAuthEnabled)
	assert.False(t, response.HasValidToken)
	assert.Equal(t, "password", response.AuthType)
	assert.False(t, response.IdentityCapabilities.LocalUsers)
	assert.False(t, response.IdentityCapabilities.OIDCLogin)
	assert.False(t, response.IdentityCapabilities.Organizations)
	assert.False(t, response.IdentityCapabilities.Roles)
	assert.False(t, response.IdentityCapabilities.AccessProfiles)
	assert.False(t, response.IdentityCapabilities.Projects)
	assert.False(t, response.IdentityCapabilities.UserAnalytics)
}
