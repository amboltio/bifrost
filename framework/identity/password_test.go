package identity

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestPasswordServiceHashesAndVerifiesArgon2id(t *testing.T) {
	service := NewPasswordService()
	hash, err := service.Hash("a sufficiently long password")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(hash, "$argon2id$v=1$"))

	verified, upgrade, err := service.VerifyAndUpgrade(hash, "a sufficiently long password")
	require.NoError(t, err)
	assert.True(t, verified)
	assert.Empty(t, upgrade)

	verified, _, err = service.VerifyAndUpgrade(hash, "wrong password")
	require.NoError(t, err)
	assert.False(t, verified)
}

func TestPasswordServiceUpgradesLegacyBcryptAndRejectsUnboundedHashes(t *testing.T) {
	service := NewPasswordService()
	legacy, err := bcrypt.GenerateFromPassword([]byte("legacy password"), bcrypt.MinCost)
	require.NoError(t, err)

	verified, upgrade, err := service.VerifyAndUpgrade(string(legacy), "legacy password")
	require.NoError(t, err)
	assert.True(t, verified)
	assert.True(t, strings.HasPrefix(upgrade, "$argon2id$v=1$"))

	verified, _, err = service.VerifyAndUpgrade("$argon2id$v=1$m=999999,t=1,p=1$c2FsdA$aGFzaA", "anything")
	require.Error(t, err)
	assert.False(t, verified)

	_, err = service.Hash(strings.Repeat("x", MaxPasswordInputBytes+1))
	require.Error(t, err)
}
