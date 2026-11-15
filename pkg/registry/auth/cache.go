package auth

import (
	"container/list"
	"context"
	"errors"
	"reflect"
	"sync"
	"time"

	"github.com/PabloMz85/watchtower/pkg/clock"
)

const (
	defaultCapacity = 1024
	maxCapacity     = 65536
	maxTTL          = 24 * time.Hour
	expiryMargin    = 5 * time.Second
	maxTokenBytes   = 16384
)

// TokenKey is an opaque, per-client HMAC. It never contains credentials.
type TokenKey [32]byte

// TokenEntry is a finite-lived bearer token, bound to its key and expiry by Tag.
// Backends must preserve every field exactly. The client validates it on reads.
type TokenEntry struct {
	Key       TokenKey
	Token     string
	ExpiresAt time.Time
	Tag       [32]byte
}

// TokenCache permits optional backends without coupling registry auth to storage.
// Implementations must be concurrency safe and honor context cancellation.
// A miss is (TokenEntry{}, false, nil). Errors must not contain secrets; the
// client nevertheless replaces all backend errors with a fixed safe message.
type TokenCache interface {
	Get(context.Context, TokenKey) (TokenEntry, bool, error)
	Set(context.Context, TokenKey, TokenEntry) error
	Delete(context.Context, TokenKey) error
}

type memoryItem struct {
	key   TokenKey
	entry TokenEntry
}

// MemoryCache is a bounded concurrent LRU; it has no background goroutines.
// Construct it with NewMemoryCache; its zero value returns an error.
type MemoryCache struct {
	mu       sync.Mutex
	clock    clock.Clock
	capacity int
	entries  map[TokenKey]*list.Element
	lru      *list.List
}

func isNil(value interface{}) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return v.IsNil()
	}
	return false
}

// NewMemoryCache requires a real instance clock and a bounded positive capacity.
func NewMemoryCache(c clock.Clock, capacity int) (*MemoryCache, error) {
	if isNil(c) || capacity < 1 || capacity > maxCapacity {
		return nil, errors.New("invalid token cache clock or capacity")
	}
	return &MemoryCache{clock: c, capacity: capacity, entries: make(map[TokenKey]*list.Element), lru: list.New()}, nil
}

func validToken(token string) bool {
	if len(token) == 0 || len(token) > maxTokenBytes {
		return false
	}
	padding := false
	for _, ch := range token {
		if ch == '=' {
			padding = true
			continue
		}
		if padding || !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || stringsTokenChar(ch)) {
			return false
		}
	}
	return token[0] != '='
}
func stringsTokenChar(ch rune) bool {
	return ch == '-' || ch == '.' || ch == '_' || ch == '~' || ch == '+' || ch == '/'
}

func validEntry(key TokenKey, entry TokenEntry, now time.Time) bool {
	return key != (TokenKey{}) && entry.Key == key && validToken(entry.Token) && entry.ExpiresAt.After(now) && !entry.ExpiresAt.After(now.Add(maxTTL))
}

func (m *MemoryCache) ready() bool {
	return m != nil && !isNil(m.clock) && m.lru != nil && m.entries != nil
}
func (m *MemoryCache) Get(ctx context.Context, key TokenKey) (TokenEntry, bool, error) {
	if ctx == nil {
		return TokenEntry{}, false, errors.New("context is required")
	}
	if err := ctx.Err(); err != nil {
		return TokenEntry{}, false, err
	}
	if !m.ready() || key == (TokenKey{}) {
		return TokenEntry{}, false, errors.New("invalid token cache")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return TokenEntry{}, false, err
	}
	if e, ok := m.entries[key]; ok {
		item := e.Value.(memoryItem)
		if !item.entry.ExpiresAt.After(m.clock.Now()) {
			m.lru.Remove(e)
			delete(m.entries, key)
			return TokenEntry{}, false, nil
		}
		m.lru.MoveToFront(e)
		return item.entry, true, nil
	}
	return TokenEntry{}, false, nil
}
func (m *MemoryCache) Set(ctx context.Context, key TokenKey, entry TokenEntry) error {
	if ctx == nil {
		return errors.New("context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !m.ready() {
		return errors.New("invalid token cache")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	now := m.clock.Now()
	if !validEntry(key, entry, now) {
		return errors.New("invalid token cache entry")
	}
	// Sweep expired entries before evicting a live token. Work is capacity bounded.
	for k, e := range m.entries {
		if !e.Value.(memoryItem).entry.ExpiresAt.After(now) {
			m.lru.Remove(e)
			delete(m.entries, k)
		}
	}
	if e, ok := m.entries[key]; ok {
		e.Value = memoryItem{key, entry}
		m.lru.MoveToFront(e)
		return nil
	}
	if m.lru.Len() >= m.capacity {
		e := m.lru.Back()
		delete(m.entries, e.Value.(memoryItem).key)
		m.lru.Remove(e)
	}
	m.entries[key] = m.lru.PushFront(memoryItem{key, entry})
	return nil
}
func (m *MemoryCache) Delete(ctx context.Context, key TokenKey) error {
	if ctx == nil {
		return errors.New("context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !m.ready() || key == (TokenKey{}) {
		return errors.New("invalid token cache")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if e, ok := m.entries[key]; ok {
		m.lru.Remove(e)
		delete(m.entries, key)
	}
	return nil
}
