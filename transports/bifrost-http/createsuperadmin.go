package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/mail"
	"os"
	"path/filepath"
	"strings"

	bifrost "github.com/maximhq/bifrost/core"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/configstore"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/maximhq/bifrost/framework/encrypt"
	"github.com/maximhq/bifrost/framework/identity"
	"golang.org/x/term"
)

func runCreateSuperAdmin(ctx context.Context, args []string) error {
	var hidden func() ([]byte, error)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		hidden = func() ([]byte, error) { return term.ReadPassword(int(os.Stdin.Fd())) }
	}
	return createSuperAdmin(ctx, args, os.Stdin, os.Stdout, hidden)
}

// createSuperAdmin keeps terminal input separate from persistence so all input
// validation completes before the config store is opened or migrated.
func createSuperAdmin(ctx context.Context, args []string, input io.Reader, output io.Writer, hidden func() ([]byte, error)) error {
	flags := flag.NewFlagSet("createsuperadmin", flag.ContinueOnError)
	flags.SetOutput(output)
	appDir := os.Getenv("APP_DIR")
	if appDir == "" {
		appDir = "."
	}
	flags.StringVar(&appDir, "app-dir", appDir, "Application data directory containing config.json and config.db")
	email := flags.String("email", "", "Administrator email")
	name := flags.String("display-name", "", "Administrator display name")
	passwordStdin := flags.Bool("password-stdin", false, "Read a single password from standard input")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	if *passwordStdin {
		if strings.TrimSpace(*email) == "" || strings.TrimSpace(*name) == "" {
			return fmt.Errorf("--password-stdin requires --email and --display-name")
		}
	} else {
		if hidden == nil {
			return fmt.Errorf("interactive input requires a terminal; use --password-stdin with --email and --display-name")
		}
		if strings.TrimSpace(*email) == "" {
			fmt.Fprint(output, "Email: ")
			value, err := readSuperAdminLine(input, 320)
			if err != nil {
				return fmt.Errorf("read email: %w", err)
			}
			*email = value
		}
		if strings.TrimSpace(*name) == "" {
			fmt.Fprint(output, "Display name: ")
			value, err := readSuperAdminLine(input, 255)
			if err != nil {
				return fmt.Errorf("read display name: %w", err)
			}
			*name = value
		}
	}
	*email = strings.TrimSpace(*email)
	address, err := mail.ParseAddress(*email)
	if err != nil || address.Address != *email || !strings.Contains(*email, "@") || len(*email) > 320 {
		return fmt.Errorf("a valid email address is required")
	}
	*name = strings.TrimSpace(*name)
	if *name == "" || len(*name) > 255 {
		return fmt.Errorf("display name must contain between 1 and 255 bytes")
	}
	var password []byte
	if *passwordStdin {
		password, err = io.ReadAll(io.LimitReader(input, identity.MaxPasswordInputBytes+3))
		if err != nil {
			return fmt.Errorf("could not read password from stdin")
		}
		password = []byte(strings.TrimSuffix(strings.TrimSuffix(string(password), "\n"), "\r"))
		if strings.ContainsAny(string(password), "\r\n") {
			clear(password)
			return fmt.Errorf("stdin must contain a single password")
		}
	} else {
		fmt.Fprint(output, "Password: ")
		password, err = hidden()
		fmt.Fprintln(output)
		if err != nil {
			clear(password)
			return fmt.Errorf("could not read hidden password")
		}
		fmt.Fprint(output, "Password (again): ")
		confirmation, readErr := hidden()
		fmt.Fprintln(output)
		match := subtle.ConstantTimeCompare(password, confirmation) == 1
		clear(confirmation)
		if readErr != nil || !match {
			clear(password)
			return fmt.Errorf("password confirmation did not match or could not be read")
		}
	}
	defer clear(password)
	verifier, err := identity.NewPasswordService().Hash(string(password))
	if err != nil {
		return err
	}
	store, policy, err := openSuperAdminStore(ctx, appDir)
	if err != nil {
		return err
	}
	defer store.Close(ctx)
	_, err = store.CreateLocalSuperAdmin(ctx, &tables.TableUser{Email: email, DisplayName: *name}, &tables.TableCredential{Kind: tables.CredentialKindPassword, SecretHash: verifier, IsActive: true}, policy)
	if err != nil {
		return fmt.Errorf("create superadmin: %w", err)
	}
	fmt.Fprintf(output, "Superadmin %s created. Sign in with this email and password.\n", *email)
	return nil
}

func readSuperAdminLine(input io.Reader, max int) (string, error) {
	data := make([]byte, 0, 64)
	var b [1]byte
	for len(data) <= max {
		n, err := input.Read(b[:])
		if n > 0 {
			if b[0] == '\n' {
				return strings.TrimSuffix(string(data), "\r"), nil
			}
			data = append(data, b[0])
		}
		if err != nil {
			return "", err
		}
	}
	return "", fmt.Errorf("input exceeds %d bytes", max)
}

// openSuperAdminStore intentionally loads only store/encryption/login metadata.
// It never loads providers, integrations, log stores or HTTP server state.
func openSuperAdminStore(ctx context.Context, appDir string) (*configstore.RDBConfigStore, *configstore.AuthConfig, error) {
	var config struct {
		Store         json.RawMessage         `json:"config_store"`
		EncryptionKey *schemas.SecretVar      `json:"encryption_key"`
		Auth          *configstore.AuthConfig `json:"auth_config"`
		Governance    *struct {
			Auth *configstore.AuthConfig `json:"auth_config"`
		} `json:"governance"`
	}
	data, err := os.ReadFile(filepath.Join(appDir, "config.json"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, nil, fmt.Errorf("read config.json: %w", err)
	}
	if err == nil {
		if err = json.Unmarshal(data, &config); err != nil {
			return nil, nil, fmt.Errorf("invalid config.json: %w", err)
		}
		if strings.TrimSpace(string(data)) == "null" {
			return nil, nil, fmt.Errorf("config.json must contain an object")
		}
	}
	if config.Governance != nil && config.Governance.Auth != nil {
		if config.Auth != nil && !config.Auth.Equivalent(*config.Governance.Auth) {
			return nil, nil, fmt.Errorf("conflicting authentication configuration")
		}
		config.Auth = config.Governance.Auth
	}
	var storeConfig configstore.Config
	if len(config.Store) > 0 {
		if string(config.Store) == "null" {
			return nil, nil, fmt.Errorf("config_store must not be null")
		}
		if err = json.Unmarshal(config.Store, &storeConfig); err != nil {
			return nil, nil, fmt.Errorf("invalid config_store: %w", err)
		}
		if !storeConfig.Enabled {
			return nil, nil, fmt.Errorf("config_store is disabled; no persistent identity store is available")
		}
	} else {
		storeConfig = configstore.Config{Enabled: true, Type: configstore.ConfigStoreTypeSQLite, Config: &configstore.SQLiteConfig{Path: filepath.Join(appDir, "config.db")}}
	}
	switch cfg := storeConfig.Config.(type) {
	case *configstore.SQLiteConfig:
		if strings.TrimSpace(cfg.Path) == "" {
			return nil, nil, fmt.Errorf("configured SQLite path is required")
		}
	case *configstore.PostgresConfig:
		for _, secret := range []*schemas.SecretVar{cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.DBName, cfg.SSLMode} {
			if secret != nil && secret.IsFromSecret() && secret.GetValue() == "" {
				return nil, nil, fmt.Errorf("configured PostgreSQL secret could not be resolved")
			}
		}
	default:
		return nil, nil, fmt.Errorf("unsupported config_store configuration")
	}
	key := config.EncryptionKey.GetValue()
	if key == "" {
		key = os.Getenv("BIFROST_ENCRYPTION_KEY")
		if key == "" && config.EncryptionKey != nil && config.EncryptionKey.IsFromSecret() {
			return nil, nil, fmt.Errorf("configured encryption key could not be resolved")
		}
	}
	if err = os.MkdirAll(appDir, 0700); err != nil {
		return nil, nil, fmt.Errorf("create application directory: %w", err)
	}
	cliLogger := bifrost.NewDefaultLogger(schemas.LogLevelError)
	encrypt.Init(key, cliLogger)
	store, err := configstore.NewConfigStore(ctx, &storeConfig, cliLogger)
	if err != nil {
		return nil, nil, fmt.Errorf("could not open configured identity store; check database settings and encryption key")
	}
	rdb, ok := store.(*configstore.RDBConfigStore)
	if !ok {
		if store != nil {
			_ = store.Close(ctx)
		}
		return nil, nil, fmt.Errorf("config store does not support local administrator provisioning")
	}
	return rdb, config.Auth, nil
}
