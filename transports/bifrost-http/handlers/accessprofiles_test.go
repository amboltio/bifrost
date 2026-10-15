package handlers

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAccessProfileRequestRejectsUnsupportedPolicyFields(t *testing.T) {
	var request accessProfileRequest
	err := json.Unmarshal([]byte(`{"name":"engineering","budgets":[{"budget_id":"monthly"}]}`), &request)
	require.Error(t, err, "unsupported policy fields must not be silently discarded")
}
