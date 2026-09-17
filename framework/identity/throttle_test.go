package identity

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLoginThrottleSharesAccountAndClientBudgets(t *testing.T) {
	now := time.Date(2026, time.September, 17, 13, 0, 0, 0, time.UTC)
	throttle := NewLoginThrottle(LoginThrottleConfig{AccountLimit: 2, ClientIPLimit: 3, Window: time.Minute, MaxEntries: 10})
	assert.True(t, throttle.Allow("alice@example.test", "203.0.113.1", now))
	assert.True(t, throttle.Allow("alice@example.test", "203.0.113.2", now))
	assert.False(t, throttle.Allow("alice@example.test", "203.0.113.3", now))
	assert.True(t, throttle.Allow("alice@example.test", "203.0.113.3", now.Add(time.Minute)))
}
