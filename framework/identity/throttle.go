package identity

import (
	"strings"
	"sync"
	"time"
)

// LoginThrottleConfig controls a bounded in-process admission budget. The
// service can be backed by a shared record in a multi-replica deployment; this
// implementation remains deliberately deterministic for the local fallback.
type LoginThrottleConfig struct {
	AccountLimit  int
	ClientIPLimit int
	Window        time.Duration
	MaxEntries    int
}

type throttleBucket struct {
	attempts []time.Time
	lastSeen time.Time
}

// LoginThrottle combines account and trusted-client-IP limits. A rejected
// request consumes neither budget, avoiding a malicious account from draining
// unrelated IP capacity.
type LoginThrottle struct {
	config  LoginThrottleConfig
	mu      sync.Mutex
	buckets map[string]throttleBucket
}

// NewLoginThrottle applies conservative bounded defaults.
func NewLoginThrottle(config LoginThrottleConfig) *LoginThrottle {
	if config.AccountLimit <= 0 {
		config.AccountLimit = 5
	}
	if config.ClientIPLimit <= 0 {
		config.ClientIPLimit = 20
	}
	if config.Window <= 0 {
		config.Window = time.Minute
	}
	if config.MaxEntries <= 0 {
		config.MaxEntries = 4096
	}
	return &LoginThrottle{config: config, buckets: make(map[string]throttleBucket)}
}

// Allow admits the next password attempt only if both scopes are below their
// rolling-window limits.
func (t *LoginThrottle) Allow(identifier, clientIP string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now = now.UTC()
	accountKey := "account:" + strings.ToLower(strings.TrimSpace(identifier))
	ipKey := "ip:" + strings.TrimSpace(clientIP)
	account := t.current(accountKey, now)
	ip := t.current(ipKey, now)
	if len(account.attempts) >= t.config.AccountLimit || len(ip.attempts) >= t.config.ClientIPLimit {
		return false
	}
	account.attempts = append(account.attempts, now)
	account.lastSeen = now
	ip.attempts = append(ip.attempts, now)
	ip.lastSeen = now
	t.buckets[accountKey] = account
	t.buckets[ipKey] = ip
	t.evict(now)
	return true
}

func (t *LoginThrottle) current(key string, now time.Time) throttleBucket {
	bucket := t.buckets[key]
	cutoff := now.Add(-t.config.Window)
	kept := bucket.attempts[:0]
	for _, attempt := range bucket.attempts {
		if attempt.After(cutoff) {
			kept = append(kept, attempt)
		}
	}
	bucket.attempts = kept
	return bucket
}

func (t *LoginThrottle) evict(now time.Time) {
	cutoff := now.Add(-t.config.Window)
	for key, bucket := range t.buckets {
		if len(bucket.attempts) == 0 && !bucket.lastSeen.After(cutoff) {
			delete(t.buckets, key)
		}
	}
	for len(t.buckets) > t.config.MaxEntries {
		var oldestKey string
		var oldest time.Time
		for key, bucket := range t.buckets {
			if oldestKey == "" || bucket.lastSeen.Before(oldest) {
				oldestKey, oldest = key, bucket.lastSeen
			}
		}
		delete(t.buckets, oldestKey)
	}
}
