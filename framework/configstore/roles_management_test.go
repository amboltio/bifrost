package configstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/stretchr/testify/require"
)

func roleAuditFixtures() (*tables.TableAuditEvent, *tables.TableOutboxEvent) {
	return &tables.TableAuditEvent{
		ActorPrincipal: "user:operator",
		TargetType:     "role",
		TargetID:       stringPointerForTest("role"),
		Action:         "identity.role.changed",
		OccurredAt:     time.Now().UTC(),
	}, &tables.TableOutboxEvent{
		Topic:            "identity.role.changed",
		DeduplicationKey: "identity.role:" + uuid.NewString(),
		Payload:          map[string]any{"role_id": "role"},
	}
}

func stringPointerForTest(value string) *string { return &value }

func TestRoleManagementCreatesUpdatesAndDeletesMutableRoles(t *testing.T) {
	store := setupIdentityTestStore(t, ":memory:")
	ctx := context.Background()

	audit, outbox := roleAuditFixtures()
	role, err := store.CreateRoleAudited(ctx, &tables.TableRole{Name: "operator", DisplayName: "Operator", Permissions: []string{"users.read"}}, audit, outbox)
	require.NoError(t, err)
	require.NotEmpty(t, role.ID)
	require.Equal(t, []string{"users.read"}, role.Permissions)

	audit, outbox = roleAuditFixtures()
	updated, err := store.UpdateRoleAudited(ctx, role.ID, "Operations", []string{"users.update", "users.read", "users.read"}, audit, outbox)
	require.NoError(t, err)
	require.Equal(t, "Operations", updated.DisplayName)
	require.Equal(t, []string{"users.read", "users.update"}, updated.Permissions)

	audit, outbox = roleAuditFixtures()
	require.NoError(t, store.DeleteRoleAudited(ctx, role.ID, audit, outbox))
	deleted, err := store.GetRole(ctx, role.ID)
	require.NoError(t, err)
	require.Nil(t, deleted)
}

func TestRoleManagementRejectsUnknownPermissionAndImmutableRole(t *testing.T) {
	store := setupIdentityTestStore(t, ":memory:")
	ctx := context.Background()

	audit, outbox := roleAuditFixtures()
	_, err := store.CreateRoleAudited(ctx, &tables.TableRole{Name: "bad", DisplayName: "Bad", Permissions: []string{"root.escape"}}, audit, outbox)
	require.ErrorIs(t, err, ErrInvalidPermission)

	audit, outbox = roleAuditFixtures()
	_, err = store.UpdateRoleAudited(ctx, tables.RoleIDSuperAdmin, "Renamed", nil, audit, outbox)
	require.ErrorIs(t, err, ErrRoleImmutable)

	audit, outbox = roleAuditFixtures()
	require.ErrorIs(t, store.DeleteRoleAudited(ctx, tables.RoleIDSuperAdmin, audit, outbox), ErrRoleImmutable)

	var eventCount int64
	require.NoError(t, store.DB().Model(&tables.TableAuditEvent{}).Count(&eventCount).Error)
	require.Equal(t, int64(0), eventCount, "rejected mutations must not append audit rows")
	if !errors.Is(err, ErrRoleImmutable) {
		t.Fatalf("expected immutable role error, got %v", err)
	}
}
