package configstore

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/stretchr/testify/require"
)

func TestBusinessUnitManagementPreservesMembershipSourceAndBlocksDelete(t *testing.T) {
	store := setupIdentityTestStore(t, ":memory:")
	ctx := context.Background()
	user := &tables.TableUser{ID: uuid.NewString(), Email: stringPointerForTest("owner@example.com"), DisplayName: "Owner", Status: tables.UserStatusActive}
	require.NoError(t, store.CreateUser(ctx, user))

	audit, outbox := roleAuditFixtures()
	unit, err := store.CreateBusinessUnitAudited(ctx, &tables.TableBusinessUnit{ID: uuid.NewString(), Name: "Platform", Description: "Core platform"}, audit, outbox)
	require.NoError(t, err)

	audit, outbox = roleAuditFixtures()
	require.NoError(t, store.ReplaceManualUserBusinessUnitMembershipsAudited(ctx, user.ID, []string{unit.ID}, nil, audit, outbox))
	memberships, err := store.ListUserBusinessUnitMemberships(ctx, user.ID)
	require.NoError(t, err)
	require.Len(t, memberships, 1)
	require.Equal(t, tables.BusinessUnitSourceManual, memberships[0].Source)

	audit, outbox = roleAuditFixtures()
	require.ErrorIs(t, store.DeleteBusinessUnitAudited(ctx, unit.ID, audit, outbox), ErrBusinessUnitInUse)

	audit, outbox = roleAuditFixtures()
	updated, err := store.UpdateBusinessUnitAudited(ctx, unit.ID, "Platform Engineering", "Core services", nil, audit, outbox)
	require.NoError(t, err)
	require.Equal(t, "Platform Engineering", updated.Name)
}
