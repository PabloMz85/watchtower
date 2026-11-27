package auth

import (
	"container/list"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/PabloMz85/watchtower/pkg/clock"
	"github.com/PabloMz85/watchtower/pkg/types"
	ref "github.com/distribution/reference"
)

// ClientOptions configures one independent auth/cache/trust domain. Nil Clock
// and Cache select RealClock and a 1024-entry RAM cache; typed nil is rejected.
// A zero Timeout selects 30 seconds. No insecure transport option is provided.
type ClientOptions struct {
	Clock   clock.Clock
	Cache   TokenCache
	CAFile  string
	Timeout time.Duration
}

type route struct {
	id      TokenKey
	key     TokenKey
	expires time.Time
}

// Client owns its cache, clock, transport and random HMAC key. It must not be
// copied. The cancellation-aware gate coalesces concurrent misses without an
// unbounded flight map or background refresh goroutines. Slow misses serialize;
// each HTTP operation has a finite timeout, and waiters may cancel independently.
type Client struct {
	clock  clock.Clock
	cache  TokenCache
	http   *http.Client
	secret [32]byte
	gate   chan struct{}
	routes map[TokenKey]*list.Element
	lru    *list.List
	// A failed rejection deletion makes the backend unsafe until replacement.
	cacheRejected bool
}

func NewClient(options ClientOptions) (*Client, error) {
	if options.Clock == nil {
		options.Clock = clock.RealClock{}
	} else if isNil(options.Clock) {
		return nil, errors.New("nil registry clock")
	}
	if options.Cache != nil && isNil(options.Cache) {
		return nil, errors.New("nil registry token cache")
	}
	if options.Timeout == 0 {
		options.Timeout = 30 * time.Second
	}
	if options.Timeout < 0 || options.Timeout > 5*time.Minute {
		return nil, errors.New("invalid registry HTTP timeout")
	}
	if options.Cache == nil {
		cache, err := NewMemoryCache(options.Clock, defaultCapacity)
		if err != nil {
			return nil, err
		}
		options.Cache = cache
	}
	httpClient, err := newHTTPClient(options.CAFile, options.Timeout)
	if err != nil {
		return nil, err
	}
	c := &Client{clock: options.Clock, cache: options.Cache, http: httpClient, gate: make(chan struct{}, 1), routes: make(map[TokenKey]*list.Element), lru: list.New()}
	if _, err := rand.Read(c.secret[:]); err != nil {
		httpClient.CloseIdleConnections()
		return nil, errors.New("could not initialize registry cache identity")
	}
	return c, nil
}

// Close releases idle connections; no persistent tokens are written.
func (c *Client) Close() {
	if c != nil && c.http != nil {
		c.http.CloseIdleConnections()
	}
}
func (c *Client) lock(ctx context.Context) error {
	if c == nil || c.gate == nil || ctx == nil {
		return errors.New("registry client and context are required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case c.gate <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-c.gate
			return err
		}
		if c.cacheRejected {
			<-c.gate
			return errors.New("registry token cache requires replacement after failed invalidation")
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (c *Client) unlock() { <-c.gate }

// Length prefixes and domain separation make tuple boundaries unambiguous.
func (c *Client) key(domain string, fields ...string) TokenKey {
	mac := hmac.New(sha256.New, c.secret[:])
	all := append([]string{domain}, fields...)
	for _, field := range all {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(field)))
		mac.Write(size[:])
		mac.Write([]byte(field))
	}
	var key TokenKey
	copy(key[:], mac.Sum(nil))
	return key
}
func (c *Client) tag(entry TokenEntry) [32]byte {
	return c.key("entry-v1", string(entry.Key[:]), entry.Token, entry.ExpiresAt.UTC().Format(time.RFC3339Nano))
}
func cacheError(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errors.New("registry token cache operation failed")
}
func (c *Client) cached(ctx context.Context, key TokenKey) (TokenEntry, bool, error) {
	entry, ok, err := c.cache.Get(ctx, key)
	if err != nil {
		return TokenEntry{}, false, cacheError(ctx)
	}
	if err := ctx.Err(); err != nil {
		return TokenEntry{}, false, err
	}
	if !ok {
		return TokenEntry{}, false, nil
	}
	tag := c.tag(entry)
	if entry.Key != key || !validToken(entry.Token) || !hmac.Equal(tag[:], entry.Tag[:]) || entry.ExpiresAt.After(c.clock.Now().Add(maxTTL)) {
		return TokenEntry{}, false, errors.New("invalid registry token cache entry")
	}
	if !entry.ExpiresAt.After(c.clock.Now()) {
		if err := c.cache.Delete(ctx, key); err != nil {
			return TokenEntry{}, false, cacheError(ctx)
		}
		return TokenEntry{}, false, nil
	}
	return entry, true, nil
}
func (c *Client) remember(id TokenKey, entry TokenEntry) {
	if e, ok := c.routes[id]; ok {
		c.lru.Remove(e)
		delete(c.routes, id)
	}
	now := c.clock.Now()
	for k, e := range c.routes {
		if !e.Value.(route).expires.After(now) {
			c.lru.Remove(e)
			delete(c.routes, k)
		}
	}
	if c.lru.Len() >= defaultCapacity {
		e := c.lru.Back()
		delete(c.routes, e.Value.(route).id)
		c.lru.Remove(e)
	}
	c.routes[id] = c.lru.PushFront(route{id, entry.Key, entry.ExpiresAt})
}

// Authorization carries a request's header and private cache identity. Retain it
// until the manifest response is known, so invalidation survives route eviction.
// Header is sensitive and must never be logged.
type Authorization struct {
	Header string
	key    TokenKey
	tag    [32]byte
}

func authorization(entry TokenEntry) Authorization {
	return Authorization{Header: "Bearer " + entry.Token, key: entry.Key, tag: entry.Tag}
}

// GetToken preserves a convenient string API for callers not needing rejection
// invalidation. Manifest callers should retain the GetAuthorization handle.
func (c *Client) GetToken(ctx context.Context, container types.Container, registryAuth string) (string, error) {
	value, err := c.GetAuthorization(ctx, container, registryAuth)
	return value.Header, err
}

// GetAuthorization authenticates using instance cache reuse, including avoiding
// repeated challenge requests while the corresponding token remains fresh.
func (c *Client) GetAuthorization(ctx context.Context, container types.Container, registryAuth string) (Authorization, error) {
	if isNil(container) {
		return Authorization{}, errors.New("container is required")
	}
	image, err := ref.ParseNormalizedNamed(container.ImageName())
	if err != nil {
		return Authorization{}, errors.New("invalid registry image reference")
	}
	if len(registryAuth) > maxTokenBytes || strings.ContainsAny(registryAuth, "\r\n\x00") {
		return Authorization{}, errors.New("invalid registry credentials")
	}
	if err := c.lock(ctx); err != nil {
		return Authorization{}, err
	}
	defer c.unlock()
	id := c.key("route-v1", image.Name(), registryAuth)
	if e, ok := c.routes[id]; ok {
		entry, hit, err := c.cached(ctx, e.Value.(route).key)
		if err != nil {
			return Authorization{}, err
		}
		if hit {
			c.lru.MoveToFront(e)
			return authorization(entry), nil
		}
		c.lru.Remove(e)
		delete(c.routes, id)
	}
	endpoint := GetChallengeURL(image)
	req, err := GetChallengeRequest(endpoint)
	if err != nil {
		return Authorization{}, err
	}
	response, err := c.Do(ctx, req)
	if err != nil {
		return Authorization{}, err
	}
	challenge := response.Header.Get(ChallengeHeader)
	if _, err := boundedBody(ctx, response); err != nil {
		return Authorization{}, err
	}
	if response.StatusCode != http.StatusUnauthorized && response.StatusCode != http.StatusOK {
		return Authorization{}, &StatusError{Code: response.StatusCode}
	}
	scheme, _, _ := strings.Cut(strings.TrimSpace(challenge), " ")
	if strings.EqualFold(scheme, "basic") {
		if registryAuth == "" || !validToken(registryAuth) {
			return Authorization{}, errors.New("no valid registry credentials available")
		}
		return Authorization{Header: "Basic " + registryAuth}, nil
	}
	authURL, err := GetAuthURL(challenge, image)
	if err != nil {
		return Authorization{}, err
	}
	entry, err := c.bearer(ctx, authURL, registryAuth, image.Name())
	if err != nil {
		return Authorization{}, err
	}
	c.remember(id, entry)
	return authorization(entry), nil
}

func (c *Client) GetBearerHeader(ctx context.Context, challenge string, image ref.Named, registryAuth string) (string, error) {
	if isNil(image) {
		return "", errors.New("image reference is required")
	}
	endpoint, err := GetAuthURL(challenge, image)
	if err != nil {
		return "", err
	}
	if len(registryAuth) > maxTokenBytes || strings.ContainsAny(registryAuth, "\r\n\x00") {
		return "", errors.New("invalid registry credentials")
	}
	if err := c.lock(ctx); err != nil {
		return "", err
	}
	defer c.unlock()
	entry, err := c.bearer(ctx, endpoint, registryAuth, image.Name())
	if err != nil {
		return "", err
	}
	return "Bearer " + entry.Token, nil
}
func (c *Client) bearer(ctx context.Context, endpoint *url.URL, registryAuth, registryImage string) (TokenEntry, error) {
	// URL includes the realm (case intact), service, and computed repository scope;
	// image.Name additionally isolates registries sharing one token service.
	key := c.key("token-v1", endpoint.String(), registryImage, registryAuth)
	if entry, hit, err := c.cached(ctx, key); err != nil || hit {
		return entry, err
	}
	req, err := http.NewRequest(http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return TokenEntry{}, errors.New("invalid registry token request")
	}
	if registryAuth != "" {
		if !validToken(registryAuth) {
			return TokenEntry{}, errors.New("invalid registry credentials")
		}
		req.Header.Set("Authorization", "Basic "+registryAuth)
	}
	response, err := c.Do(ctx, req)
	if err != nil {
		return TokenEntry{}, err
	}
	body, err := boundedBody(ctx, response)
	if err != nil {
		return TokenEntry{}, err
	}
	if response.StatusCode != http.StatusOK {
		return TokenEntry{}, &StatusError{Code: response.StatusCode}
	}
	// Without issued_at, registry lifetimes start when the exchange completes.
	// A server can also legitimately issue a token after the request began.
	entry, err := parseToken(body, c.clock.Now())
	if err != nil {
		return TokenEntry{}, err
	}
	if !entry.ExpiresAt.After(c.clock.Now()) {
		return TokenEntry{}, errors.New("registry token expired during request")
	}
	entry.Key = key
	entry.Tag = c.tag(entry)
	if err := c.cache.Set(ctx, key, entry); err != nil {
		return TokenEntry{}, cacheError(ctx)
	}
	if err := ctx.Err(); err != nil {
		return TokenEntry{}, err
	}
	return entry, nil
}
func parseToken(body []byte, now time.Time) (TokenEntry, error) {
	var response struct {
		Token       string          `json:"token"`
		AccessToken string          `json:"access_token"`
		ExpiresIn   json.RawMessage `json:"expires_in"`
		IssuedAt    json.RawMessage `json:"issued_at"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return TokenEntry{}, errors.New("invalid registry token response")
	}
	if response.Token == "" {
		response.Token = response.AccessToken
	} else if response.AccessToken != "" && response.Token != response.AccessToken {
		return TokenEntry{}, errors.New("conflicting registry tokens")
	}
	if !validToken(response.Token) {
		return TokenEntry{}, errors.New("invalid registry bearer token")
	}
	seconds := int64(60)
	if response.ExpiresIn != nil {
		var err error
		seconds, err = strconv.ParseInt(string(response.ExpiresIn), 10, 64)
		if err != nil || seconds <= 0 || seconds > int64(maxTTL/time.Second) {
			return TokenEntry{}, errors.New("invalid registry token lifetime")
		}
	}
	issued := now
	if response.IssuedAt != nil {
		var raw string
		if err := json.Unmarshal(response.IssuedAt, &raw); err != nil {
			return TokenEntry{}, errors.New("invalid registry token issue time")
		}
		parsed, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil || parsed.After(now) {
			return TokenEntry{}, errors.New("invalid registry token issue time")
		}
		issued = parsed
	}
	expires := issued.Add(time.Duration(seconds) * time.Second).Add(-expiryMargin)
	if !expires.After(now) {
		return TokenEntry{}, errors.New("expired registry token")
	}
	return TokenEntry{Token: response.Token, ExpiresAt: expires}, nil
}

// InvalidateAuthorization removes the exact authorization rejected by a manifest
// request, even if bounded route metadata was evicted while it was in flight.
// A late response cannot remove a different or more recently refreshed entry.
func (c *Client) InvalidateAuthorization(ctx context.Context, rejected Authorization) error {
	if err := c.lock(ctx); err != nil {
		return err
	}
	defer c.unlock()
	if rejected.key == (TokenKey{}) {
		return nil // Basic authentication has no cached bearer token.
	}
	entry, hit, err := c.cached(ctx, rejected.key)
	if err != nil {
		c.cacheRejected = true
		return err
	}
	if hit && (rejected.Header != "Bearer "+entry.Token || rejected.tag != entry.Tag) {
		return nil
	}
	for id, e := range c.routes {
		if e.Value.(route).key == rejected.key {
			c.lru.Remove(e)
			delete(c.routes, id)
		}
	}
	if err := c.cache.Delete(ctx, rejected.key); err != nil {
		c.cacheRejected = true
		return cacheError(ctx)
	}
	return nil
}
