package configstore

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/stretchr/testify/require"
)

func TestUserVirtualKeyAssignmentsRevokeAndReplaceManualRows(t *testing.T) {
	store := setupIdentityTestStore(t, ":memory:")
	ctx := context.Background()
	user := &tables.TableUser{ID: uuid.NewString(), Email: stringPointerForTest("vk-owner@example.com"), DisplayName: "VK owner", Status: tables.UserStatusActive}
	require.NoError(t, store.CreateUser(ctx, user))
	active := true
	for _, key := range []*tables.TableVirtualKey{{ID: "vk-1", Name: "Key 1", Value: *schemas.NewSecretVar("bfvk-one"), IsActive: &active}, {ID: "vk-2", Name: "Key 2", Value: *schemas.NewSecretVar("bfvk-two"), IsActive: &active}} {
		require.NoError(t, store.DB().Create(key).Error)
	}
	audit, outbox := roleAuditFixtures()
	require.NoError(t, store.ReplaceManualUserVirtualKeyAssignmentsAudited(ctx, user.ID, []string{"vk-1"}, nil, audit, outbox))
	audit, outbox = roleAuditFixtures()
	require.NoError(t, store.ReplaceManualUserVirtualKeyAssignmentsAudited(ctx, user.ID, []string{"vk-2"}, nil, audit, outbox))
	assignments, err := store.ListUserVirtualKeyAssignments(ctx, user.ID)
	require.NoError(t, err)
	require.Len(t, assignments, 1)
	require.Equal(t, "vk-2", assignments[0].VirtualKeyID)
	var revoked int64
	require.NoError(t, store.DB().Model(&tables.TableUserVirtualKeyAssignment{}).Where("user_id = ? AND revoked_at IS NOT NULL", user.ID).Count(&revoked).Error)
	require.Equal(t, int64(1), revoked)
}
