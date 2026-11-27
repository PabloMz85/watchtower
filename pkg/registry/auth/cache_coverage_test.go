package auth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type coverageCacheClock struct {
	mu  sync.Mutex
	now time.Time
}

func coverageCacheNewClock() *coverageCacheClock {
	return &coverageCacheClock{now: time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)}
}
func (c *coverageCacheClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}
func (c *coverageCacheClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}
func coverageCacheNewMemory(t *testing.T, c *coverageCacheClock, capacity int) *MemoryCache {
	t.Helper()
	m, err := NewMemoryCache(c, capacity)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
func coverageCacheEntry(c *coverageCacheClock, key TokenKey, token string, ttl time.Duration) TokenEntry {
	return TokenEntry{Key: key, Token: token, ExpiresAt: c.Now().Add(ttl), Tag: [32]byte{9}}
}
func coverageCacheWantEntry(t *testing.T, m *MemoryCache, key TokenKey, want TokenEntry, hit bool) {
	t.Helper()
	got, ok, err := m.Get(context.Background(), key)
	if err != nil || ok != hit || got != want {
		t.Fatalf("Get(%x) = (%+v, %v, %v), want (%+v, %v, nil)", key, got, ok, err, want, hit)
	}
}

func TestCoverageCacheOverwritePromotesAndReplacesLifetime(t *testing.T) {
	clock := coverageCacheNewClock()
	m := coverageCacheNewMemory(t, clock, 2)
	ctx := context.Background()
	a, b, c := TokenKey{1}, TokenKey{2}, TokenKey{3}
	for _, key := range []TokenKey{a, b} {
		if err := m.Set(ctx, key, coverageCacheEntry(clock, key, "original", time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	replacement := coverageCacheEntry(clock, a, "replacement==", 2*time.Minute)
	if err := m.Set(ctx, a, replacement); err != nil {
		t.Fatal(err)
	}
	if err := m.Set(ctx, c, coverageCacheEntry(clock, c, "third", 2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	coverageCacheWantEntry(t, m, b, TokenEntry{}, false)
	coverageCacheWantEntry(t, m, a, replacement, true)
	clock.advance(time.Minute)
	coverageCacheWantEntry(t, m, a, replacement, true)
	clock.advance(time.Minute)
	coverageCacheWantEntry(t, m, a, TokenEntry{}, false)
}

func TestCoverageCacheReadPromotesAndSweepPreservesLiveEntry(t *testing.T) {
	clock := coverageCacheNewClock()
	ctx := context.Background()
	t.Run("read promotes", func(t *testing.T) {
		m := coverageCacheNewMemory(t, clock, 2)
		a := coverageCacheEntry(clock, TokenKey{1}, "first", time.Minute)
		for _, entry := range []TokenEntry{a, coverageCacheEntry(clock, TokenKey{2}, "second", time.Minute)} {
			if err := m.Set(ctx, entry.Key, entry); err != nil {
				t.Fatal(err)
			}
		}
		coverageCacheWantEntry(t, m, a.Key, a, true)
		third := coverageCacheEntry(clock, TokenKey{3}, "third", time.Minute)
		if err := m.Set(ctx, third.Key, third); err != nil {
			t.Fatal(err)
		}
		coverageCacheWantEntry(t, m, TokenKey{2}, TokenEntry{}, false)
		coverageCacheWantEntry(t, m, a.Key, a, true)
	})
	t.Run("sweep before eviction", func(t *testing.T) {
		m := coverageCacheNewMemory(t, clock, 2)
		live := coverageCacheEntry(clock, TokenKey{1}, "live", time.Minute)
		expiring := coverageCacheEntry(clock, TokenKey{2}, "expiring", time.Second)
		for _, entry := range []TokenEntry{live, expiring} {
			if err := m.Set(ctx, entry.Key, entry); err != nil {
				t.Fatal(err)
			}
		}
		clock.advance(time.Second)
		third := coverageCacheEntry(clock, TokenKey{3}, "third", time.Minute)
		if err := m.Set(ctx, third.Key, third); err != nil {
			t.Fatal(err)
		}
		coverageCacheWantEntry(t, m, expiring.Key, TokenEntry{}, false)
		coverageCacheWantEntry(t, m, live.Key, live, true)
	})
}

func TestCoverageCacheEntryValidationDoesNotOverwrite(t *testing.T) {
	clock := coverageCacheNewClock()
	key := TokenKey{1}
	original := coverageCacheEntry(clock, key, "original", time.Minute)
	for _, test := range []struct {
		name   string
		change func(*TokenEntry)
	}{
		{"different key", func(e *TokenEntry) { e.Key = TokenKey{2} }},
		{"empty token", func(e *TokenEntry) { e.Token = "" }},
		{"leading padding", func(e *TokenEntry) { e.Token = "=abc" }},
		{"padding only", func(e *TokenEntry) { e.Token = "==" }},
		{"interior padding", func(e *TokenEntry) { e.Token = "abc=def" }},
		{"whitespace", func(e *TokenEntry) { e.Token = "abc def" }},
		{"non ASCII", func(e *TokenEntry) { e.Token = "abcé" }},
		{"over token bound", func(e *TokenEntry) { e.Token = strings.Repeat("a", maxTokenBytes+1) }},
		{"expired boundary", func(e *TokenEntry) { e.ExpiresAt = clock.Now() }},
		{"over TTL bound", func(e *TokenEntry) { e.ExpiresAt = clock.Now().Add(maxTTL + time.Nanosecond) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			m := coverageCacheNewMemory(t, clock, 1)
			if err := m.Set(context.Background(), key, original); err != nil {
				t.Fatal(err)
			}
			invalid := original
			test.change(&invalid)
			if err := m.Set(context.Background(), key, invalid); err == nil || err.Error() != "invalid token cache entry" {
				t.Fatalf("invalid replacement error = %v", err)
			}
			coverageCacheWantEntry(t, m, key, original, true)
		})
	}
	for _, token := range []string{"abc==", "AZaz09-._~+/=", strings.Repeat("a", maxTokenBytes)} {
		m := coverageCacheNewMemory(t, clock, 1)
		entry := coverageCacheEntry(clock, key, token, maxTTL)
		if err := m.Set(context.Background(), key, entry); err != nil {
			t.Fatalf("valid token/TTL boundary: %v", err)
		}
		coverageCacheWantEntry(t, m, key, entry, true)
	}
}

func TestCoverageCacheInvalidInputsHaveNoSideEffects(t *testing.T) {
	clock := coverageCacheNewClock()
	key := TokenKey{1}
	entry := coverageCacheEntry(clock, key, "preserved", time.Minute)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, op := range []string{"get", "set", "delete"} {
		for _, mode := range []string{"nil context", "cancelled", "nil cache", "zero cache", "zero key"} {
			t.Run(op+"/"+mode, func(t *testing.T) {
				m := coverageCacheNewMemory(t, clock, 1)
				if err := m.Set(context.Background(), key, entry); err != nil {
					t.Fatal(err)
				}
				target, ctx, requestKey := m, context.Context(context.Background()), key
				want := "invalid token cache"
				switch mode {
				case "nil context":
					var nilContext context.Context
					ctx, want = nilContext, "context is required"
				case "cancelled":
					ctx, want = cancelled, context.Canceled.Error()
				case "nil cache":
					target = nil
				case "zero cache":
					target = &MemoryCache{}
				case "zero key":
					requestKey = TokenKey{}
					if op == "set" {
						want = "invalid token cache entry"
					}
				}
				var err error
				switch op {
				case "get":
					var got TokenEntry
					var hit bool
					got, hit, err = target.Get(ctx, requestKey)
					if got != (TokenEntry{}) || hit {
						t.Fatalf("invalid Get exposed entry: %+v, %v", got, hit)
					}
				case "set":
					err = target.Set(ctx, requestKey, entry)
				case "delete":
					err = target.Delete(ctx, requestKey)
				}
				if err == nil || err.Error() != want {
					t.Fatalf("error = %v, want %q", err, want)
				}
				if mode == "cancelled" && !errors.Is(err, context.Canceled) {
					t.Fatalf("lost cancellation identity: %v", err)
				}
				coverageCacheWantEntry(t, m, key, entry, true)
			})
		}
	}
}

// Capture the first pre-lock check before allowing the test to cancel. No
// scheduler timing or sleeps are needed to reach the post-mutex check.
type coverageCacheObservedContext struct {
	context.Context
	checked chan struct{}
	once    sync.Once
}

func (c *coverageCacheObservedContext) Err() error {
	err := c.Context.Err()
	c.once.Do(func() { close(c.checked) })
	return err
}

func TestCoverageCacheCancellationWhileWaitingForMutex(t *testing.T) {
	for _, op := range []string{"get", "set", "delete"} {
		t.Run(op, func(t *testing.T) {
			clock := coverageCacheNewClock()
			m := coverageCacheNewMemory(t, clock, 1)
			key := TokenKey{1}
			original := coverageCacheEntry(clock, key, "original", time.Minute)
			if err := m.Set(context.Background(), key, original); err != nil {
				t.Fatal(err)
			}
			base, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx := &coverageCacheObservedContext{Context: base, checked: make(chan struct{})}
			done := make(chan error, 1)
			m.mu.Lock()
			go func() {
				switch op {
				case "get":
					entry, hit, err := m.Get(ctx, key)
					if entry != (TokenEntry{}) || hit {
						t.Errorf("cancelled read returned data: %+v, %v", entry, hit)
					}
					done <- err
				case "set":
					done <- m.Set(ctx, key, coverageCacheEntry(clock, key, "replacement", time.Minute))
				case "delete":
					done <- m.Delete(ctx, key)
				}
			}()
			<-ctx.checked
			cancel()
			m.mu.Unlock()
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Fatalf("post-lock cancellation = %v", err)
			}
			coverageCacheWantEntry(t, m, key, original, true)
		})
	}
}
