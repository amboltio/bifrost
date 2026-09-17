// Package identity contains trusted authentication lifecycle services. It
// deliberately depends on small config-store contracts rather than HTTP so
// startup, CLI, and transport wiring share the same migration semantics.
package identity

import (
	"context"
	"fmt"
	"strings"

	"github.com/maximhq/bifrost/framework/configstore"
)

// BootstrapResult reports whether a legacy admin was imported. NeedsSetup is
// true on a fresh deployment; the existing setup-token-protected config flow
// must create credentials before a later startup can import them.
type BootstrapResult struct {
	Imported   bool
	NeedsSetup bool
	UserID     string
}

// BootstrapLegacyAdmin resolves the existing auth configuration first, then
// delegates the durable, transactional import to configstore. Empty
// deployments remain in setup mode instead of inventing an in-memory admin.
func BootstrapLegacyAdmin(ctx context.Context, store configstore.LegacyAdminBootstrapStore) (*BootstrapResult, error) {
	if store == nil {
		return nil, fmt.Errorf("legacy bootstrap store is required")
	}
	authConfig, err := store.GetAuthConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load legacy admin configuration: %w", err)
	}
	if authConfig == nil || authConfig.AdminUserName == nil || authConfig.AdminPassword == nil ||
		strings.TrimSpace(authConfig.AdminUserName.GetValue()) == "" || strings.TrimSpace(authConfig.AdminPassword.GetValue()) == "" {
		return &BootstrapResult{NeedsSetup: true}, nil
	}

	result, err := store.BootstrapLegacyAdmin(ctx, configstore.LegacyAdminBootstrapInput{
		Username: authConfig.AdminUserName.GetValue(), PasswordHash: authConfig.AdminPassword.GetValue(),
	})
	if err != nil {
		return nil, err
	}
	return &BootstrapResult{Imported: result.Imported, UserID: result.User.ID}, nil
}
