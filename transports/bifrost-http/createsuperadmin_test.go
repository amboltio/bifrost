package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/framework/configstore"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/maximhq/bifrost/framework/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateSuperAdminCommandCreatesAndVerifiesPassword(t *testing.T) {
	dir := t.TempDir()
	var output bytes.Buffer
	args := []string{"--app-dir", dir, "--email", "Admin@example.test", "--display-name", "Operator", "--password-stdin"}
	require.NoError(t, createSuperAdmin(context.Background(), args, strings.NewReader("correct horse battery staple\n"), &output, nil))
	assert.NotContains(t, output.String(), "correct horse")
	store, _, err := openSuperAdminStore(context.Background(), dir)
	require.NoError(t, err)
	defer store.Close(context.Background())
	user, err := store.GetUserByNormalizedEmail(context.Background(), "admin@example.test")
	require.NoError(t, err)
	require.NotNil(t, user)
	cred, err := store.GetCredentialByUserIDAndKind(context.Background(), user.ID, tables.CredentialKindPassword)
	require.NoError(t, err)
	valid, _, err := identity.NewPasswordService().VerifyAndUpgrade(cred.SecretHash, "correct horse battery staple")
	require.NoError(t, err)
	assert.True(t, valid)
	err = createSuperAdmin(context.Background(), args, strings.NewReader("another secure password\n"), &output, nil)
	require.ErrorIs(t, err, configstore.ErrAlreadyExists)
	assert.NoFileExists(t, filepath.Join(dir, "logs.db"))
}

func TestCreateSuperAdminInputValidation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		password string
	}{
		{"empty", []string{"--email", "admin@example.test", "--display-name", "Admin", "--password-stdin"}, ""},
		{"short", []string{"--email", "admin@example.test", "--display-name", "Admin", "--password-stdin"}, "short"},
		{"large", []string{"--email", "admin@example.test", "--display-name", "Admin", "--password-stdin"}, strings.Repeat("a", 4097)},
		{"multiple lines", []string{"--email", "admin@example.test", "--display-name", "Admin", "--password-stdin"}, "a very long password\nanother password\n"},
		{"extra newline", []string{"--email", "admin@example.test", "--display-name", "Admin", "--password-stdin"}, "a very long password\n\n"},
		{"email", []string{"--email", "Admin <admin@example.test>", "--display-name", "Admin", "--password-stdin"}, "a very long password"},
		{"missing email", []string{"--display-name", "Admin", "--password-stdin"}, "a very long password"},
		{"plaintext flag", []string{"--password", "a very long password"}, ""},
		{"no terminal", []string{"--email", "admin@example.test", "--display-name", "Admin"}, "a very long password"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			args := append([]string{"--app-dir", dir}, tc.args...)
			var output bytes.Buffer
			require.Error(t, createSuperAdmin(context.Background(), args, strings.NewReader(tc.password), &output, nil))
			assert.NoFileExists(t, filepath.Join(dir, "config.db"))
		})
	}
}

func TestCreateSuperAdminInputReadFailuresDoNotOpenStore(t *testing.T) {
	for _, tc := range []struct {
		name   string
		input  string
		hidden func() ([]byte, error)
	}{
		{"email EOF", "", func() ([]byte, error) { t.Fatal("password read after email EOF"); return nil, nil }},
		{"name EOF", "admin@example.test\n", func() ([]byte, error) { t.Fatal("password read after name EOF"); return nil, nil }},
		{"hidden EOF", "admin@example.test\nAdmin\n", func() ([]byte, error) { return []byte("partial secret input"), io.EOF }},
		{"confirmation EOF", "admin@example.test\nAdmin\n", func() func() ([]byte, error) {
			calls := 0
			return func() ([]byte, error) {
				calls++
				if calls == 2 {
					return nil, io.EOF
				}
				return []byte("a very long password"), nil
			}
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			var output bytes.Buffer
			require.Error(t, createSuperAdmin(context.Background(), []string{"--app-dir", dir}, strings.NewReader(tc.input), &output, tc.hidden))
			assert.NoFileExists(t, filepath.Join(dir, "config.db"))
			assert.NotContains(t, output.String(), "secret input")
			assert.NotContains(t, output.String(), "a very long password")
		})
	}
}

func TestSuperAdminStoreExplicitSQLiteTarget(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(t.TempDir(), "gateway.db")
	raw, err := json.Marshal(map[string]any{"config_store": configstore.Config{Enabled: true, Type: configstore.ConfigStoreTypeSQLite, Config: configstore.SQLiteConfig{Path: dbPath}}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.json"), raw, 0600))
	var output bytes.Buffer
	require.NoError(t, createSuperAdmin(context.Background(), []string{"--app-dir", dir, "--email", "admin@example.test", "--display-name", "Admin", "--password-stdin"}, strings.NewReader("a very long password\r\n"), &output, nil))
	assert.FileExists(t, dbPath)
	assert.NoFileExists(t, filepath.Join(dir, "config.db"))
	store, _, err := openSuperAdminStore(context.Background(), dir)
	require.NoError(t, err)
	defer store.Close(context.Background())
	user, err := store.GetUserByNormalizedEmail(context.Background(), "admin@example.test")
	require.NoError(t, err)
	require.NotNil(t, user)
	credential, err := store.GetCredentialByUserIDAndKind(context.Background(), user.ID, tables.CredentialKindPassword)
	require.NoError(t, err)
	valid, _, err := identity.NewPasswordService().VerifyAndUpgrade(credential.SecretHash, "a very long password")
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestSuperAdminStoreWrongEncryptionKeyDoesNotCreateIdentity(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BIFROST_ENCRYPTION_KEY", "first-test-encryption-passphrase")
	var output bytes.Buffer
	args := []string{"--app-dir", dir, "--email", "admin@example.test", "--display-name", "Admin", "--password-stdin"}
	require.NoError(t, createSuperAdmin(context.Background(), args, strings.NewReader("a very long password"), &output, nil))
	t.Setenv("BIFROST_ENCRYPTION_KEY", "incorrect-encryption-passphrase")
	args[3] = "recovery@example.test"
	require.Error(t, createSuperAdmin(context.Background(), args, strings.NewReader("another long password"), &output, nil))
	t.Setenv("BIFROST_ENCRYPTION_KEY", "first-test-encryption-passphrase")
	store, _, err := openSuperAdminStore(context.Background(), dir)
	require.NoError(t, err)
	defer store.Close(context.Background())
	user, err := store.GetUserByNormalizedEmail(context.Background(), "recovery@example.test")
	require.NoError(t, err)
	assert.Nil(t, user)
	var count int64
	require.NoError(t, store.DB().Model(&tables.TableUser{}).Count(&count).Error)
	assert.Equal(t, int64(1), count)
}

func TestCreateSuperAdminInteractiveConfirmation(t *testing.T) {
	for _, match := range []bool{true, false} {
		t.Run(map[bool]string{true: "match", false: "mismatch"}[match], func(t *testing.T) {
			dir := t.TempDir()
			var output bytes.Buffer
			prompts := 0
			hidden := func() ([]byte, error) {
				prompts++
				if prompts == 2 && !match {
					return []byte("different password"), nil
				}
				return []byte("correct horse battery staple"), nil
			}
			err := createSuperAdmin(context.Background(), []string{"--app-dir", dir}, strings.NewReader("admin@example.test\nOperator\n"), &output, hidden)
			if match {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.NoFileExists(t, filepath.Join(dir, "config.db"))
			}
			assert.Equal(t, 2, prompts)
			assert.NotContains(t, output.String(), "correct horse")
		})
	}
}

func TestSuperAdminStoreRefusesUnsafeConfiguration(t *testing.T) {
	for _, raw := range []string{`{"config_store":null}`, `{"config_store":{"enabled":false,"type":"sqlite"}}`, `{"config_store":{"enabled":true,"type":"sqlite","config":{}}}`, `{"config_store":{"enabled":true,"type":"postgres","config":{"host":"env.BIFROST_CLI_MISSING_HOST"}}}`, `{"encryption_key":"env.BIFROST_CLI_MISSING_KEY"}`} {
		t.Run(raw, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "config.json"), []byte(raw), 0600))
			_, _, err := openSuperAdminStore(context.Background(), dir)
			require.Error(t, err)
			assert.NoFileExists(t, filepath.Join(dir, "config.db"))
		})
	}
}

func TestSuperAdminStoreEncryptionAndFilePolicy(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BIFROST_ENCRYPTION_KEY", "test-only-cli-encryption-passphrase")
	raw := `{"governance":{"auth_config":{"is_enabled":true,"local_login":{"is_enabled":false,"session_ttl_seconds":7200,"idle_timeout_seconds":600},"oidc_providers":[{"id":"company","display_name":"Company","type":"generic","is_enabled":true,"issuer_url":"https://id.example.test","client_id":"company-client","client_secret":"company-secret"}]}}}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.json"), []byte(raw), 0600))
	var output bytes.Buffer
	require.NoError(t, createSuperAdmin(context.Background(), []string{"--app-dir", dir, "--email", "admin@example.test", "--display-name", "Admin", "--password-stdin"}, strings.NewReader("test secure password"), &output, nil))
	store, _, err := openSuperAdminStore(context.Background(), dir)
	require.NoError(t, err)
	defer store.Close(context.Background())
	policy, err := store.GetDashboardAuthPolicy(context.Background())
	require.NoError(t, err)
	assert.True(t, policy.AuthConfig.LocalLogin.IsEnabled)
	assert.Equal(t, 7200, policy.AuthConfig.LocalLogin.SessionTTLSeconds)
	require.Len(t, policy.AuthConfig.OIDCProviders, 1)
	assert.Equal(t, "company-secret", policy.AuthConfig.OIDCProviders[0].ClientSecret.GetValue())
	var row tables.TableGovernanceConfig
	require.NoError(t, store.DB().First(&row, "key = ?", tables.ConfigDashboardAuthPolicyKey).Error)
	assert.NotContains(t, row.Value, "company-secret")
	assert.Contains(t, row.Value, `"encrypted":true`)
}
