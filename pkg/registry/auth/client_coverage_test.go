package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PabloMz85/watchtower/internal/registrytest"
	"github.com/PabloMz85/watchtower/pkg/types"
	ref "github.com/distribution/reference"
)

type coverageCacheBackend struct {
	get    func(context.Context, TokenKey) (TokenEntry, bool, error)
	set    func(context.Context, TokenKey, TokenEntry) error
	delete func(context.Context, TokenKey) error
}

func (b *coverageCacheBackend) Get(ctx context.Context, key TokenKey) (TokenEntry, bool, error) {
	if b.get != nil {
		return b.get(ctx, key)
	}
	return TokenEntry{}, false, nil
}
func (b *coverageCacheBackend) Set(ctx context.Context, key TokenKey, entry TokenEntry) error {
	if b.set != nil {
		return b.set(ctx, key, entry)
	}
	return nil
}
func (b *coverageCacheBackend) Delete(ctx context.Context, key TokenKey) error {
	if b.delete != nil {
		return b.delete(ctx, key)
	}
	return nil
}

type coverageCacheContainer struct {
	types.Container
	image string
}

func (c coverageCacheContainer) ImageName() string { return c.image }

type coverageCacheRoundTripper func(*http.Request) (*http.Response, error)

func (f coverageCacheRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func coverageCacheNewClient(t *testing.T, clock *coverageCacheClock, backend TokenCache) *Client {
	t.Helper()
	c, err := NewClient(ClientOptions{Clock: clock, Cache: backend})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}
func coverageCacheResponse(r *http.Request, status int, challenge, body string) *http.Response {
	h := make(http.Header)
	if challenge != "" {
		h.Set(ChallengeHeader, challenge)
	}
	return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(body)), Request: r}
}
func coverageCacheWantError(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %q", err, want)
	}
}

func TestCoverageCacheClientRejectsInputsBeforeIO(t *testing.T) {
	clock := coverageCacheNewClock()
	backend := &coverageCacheBackend{get: func(context.Context, TokenKey) (TokenEntry, bool, error) {
		t.Error("input validation reached cache")
		return TokenEntry{}, false, nil
	}}
	c := coverageCacheNewClient(t, clock, backend)
	c.http.Transport = coverageCacheRoundTripper(func(*http.Request) (*http.Response, error) {
		t.Error("input validation reached HTTP")
		return nil, errors.New("unexpected HTTP")
	})
	ctx := context.Background()
	got, err := c.GetAuthorization(ctx, coverageCacheContainer{image: "example.test/Bad Name"}, "")
	coverageCacheWantError(t, err, "invalid registry image reference")
	if got != (Authorization{}) {
		t.Fatal("invalid image returned authorization")
	}
	image, err := ref.ParseNormalizedNamed("example.test/team/image:latest")
	if err != nil {
		t.Fatal(err)
	}
	challenge := `Bearer realm="https://example.test/token",service="Registry"`
	for _, credential := range []string{"credential\r\ninjection", "credential\x00", strings.Repeat("a", maxTokenBytes+1)} {
		got, err = c.GetAuthorization(ctx, coverageCacheContainer{image: image.String()}, credential)
		coverageCacheWantError(t, err, "invalid registry credentials")
		if got != (Authorization{}) {
			t.Fatal("invalid credentials returned authorization")
		}
		header, err := c.GetBearerHeader(ctx, challenge, image, credential)
		coverageCacheWantError(t, err, "invalid registry credentials")
		if header != "" {
			t.Fatal("invalid credentials returned bearer header")
		}
	}
	header, err := c.GetBearerHeader(ctx, `Bearer realm="https://example.test/token"`, image, "")
	coverageCacheWantError(t, err, "registry challenge is missing realm or service")
	if header != "" {
		t.Fatal("invalid challenge returned bearer header")
	}
}

func TestCoverageCacheBasicFallbackNeverTouchesBearerCache(t *testing.T) {
	validCredential := base64.StdEncoding.EncodeToString([]byte("fixture:" + registrytest.Random(t)))
	for _, credential := range []string{"", "bad credential", validCredential} {
		t.Run(fmt.Sprintf("credential-length-%d", len(credential)), func(t *testing.T) {
			backend := &coverageCacheBackend{
				get: func(context.Context, TokenKey) (TokenEntry, bool, error) {
					t.Error("Basic read bearer cache")
					return TokenEntry{}, false, nil
				},
				set:    func(context.Context, TokenKey, TokenEntry) error { t.Error("Basic wrote bearer cache"); return nil },
				delete: func(context.Context, TokenKey) error { t.Error("Basic invalidation deleted bearer cache"); return nil },
			}
			c := coverageCacheNewClient(t, coverageCacheNewClock(), backend)
			calls := 0
			c.http.Transport = coverageCacheRoundTripper(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.String() != "https://example.test/v2/" || r.Header.Get("Authorization") != "" {
					t.Errorf("unexpected challenge request: %s, authorization present=%v", r.URL, r.Header.Get("Authorization") != "")
				}
				return coverageCacheResponse(r, 401, `bAsIc realm="Private"`, ""), nil
			})
			for range 2 {
				got, err := c.GetAuthorization(context.Background(), coverageCacheContainer{image: "example.test/team/image"}, credential)
				if credential == "" || strings.Contains(credential, " ") {
					coverageCacheWantError(t, err, "no valid registry credentials available")
					if got != (Authorization{}) {
						t.Fatal("invalid Basic credentials produced authorization")
					}
				} else {
					if err != nil || got != (Authorization{Header: "Basic " + credential}) {
						t.Fatalf("Basic fallback = %+v, %v", got, err)
					}
					if err := c.InvalidateAuthorization(context.Background(), got); err != nil {
						t.Fatal(err)
					}
				}
			}
			if calls != 2 {
				t.Fatalf("Basic challenge calls = %d, want 2 (no bearer route reuse)", calls)
			}
		})
	}
}

func TestCoverageCacheClientPropagatesMalformedChallenge(t *testing.T) {
	c := coverageCacheNewClient(t, coverageCacheNewClock(), &coverageCacheBackend{})
	calls := 0
	c.http.Transport = coverageCacheRoundTripper(func(r *http.Request) (*http.Response, error) {
		calls++
		return coverageCacheResponse(r, 401, `Bearer realm="https://example.test/token"`, ""), nil
	})
	got, err := c.GetAuthorization(context.Background(), coverageCacheContainer{image: "example.test/image"}, "")
	coverageCacheWantError(t, err, "registry challenge is missing realm or service")
	if got != (Authorization{}) || calls != 1 {
		t.Fatalf("malformed challenge produced authorization or token request: %+v, calls=%d", got, calls)
	}
}

func TestCoverageCacheCachedExpiryDeletesExactKey(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(fmt.Sprintf("delete-error-%v", failure), func(t *testing.T) {
			clock := coverageCacheNewClock()
			backend := &coverageCacheBackend{}
			c := coverageCacheNewClient(t, clock, backend)
			key := TokenKey{1}
			entry := coverageCacheEntry(clock, key, "expired", time.Minute)
			entry.Tag = c.tag(entry)
			clock.advance(time.Minute)
			backend.get = func(_ context.Context, requested TokenKey) (TokenEntry, bool, error) {
				if requested != key {
					t.Fatal("read wrong token identity")
				}
				return entry, true, nil // A backend may retain an expired, otherwise authentic entry.
			}
			deletes := 0
			backend.delete = func(_ context.Context, requested TokenKey) error {
				deletes++
				if requested != key {
					t.Fatal("deleted another token identity")
				}
				if failure {
					return errors.New("sensitive-backend-details")
				}
				return nil
			}
			got, hit, err := c.cached(context.Background(), key)
			if failure {
				coverageCacheWantError(t, err, "registry token cache operation failed")
			} else if err != nil {
				t.Fatal(err)
			}
			if hit || got != (TokenEntry{}) || deletes != 1 {
				t.Fatalf("expired read = %+v, hit=%v, deletes=%d", got, hit, deletes)
			}
		})
	}
}

func TestCoverageCacheCachedRejectsAuthenticatedEntryTampering(t *testing.T) {
	for _, mode := range []string{"tag", "token", "key", "signed invalid token", "signed overlong TTL"} {
		t.Run(mode, func(t *testing.T) {
			clock := coverageCacheNewClock()
			backend := &coverageCacheBackend{}
			c := coverageCacheNewClient(t, clock, backend)
			key := TokenKey{1}
			entry := coverageCacheEntry(clock, key, "original", time.Minute)
			entry.Tag = c.tag(entry)
			switch mode {
			case "tag":
				entry.Tag[0] ^= 1
			case "token":
				entry.Token = "changed"
			case "key":
				entry.Key = TokenKey{2}
			case "signed invalid token":
				entry.Token = "bad token"
				entry.Tag = c.tag(entry)
			case "signed overlong TTL":
				entry.ExpiresAt = clock.Now().Add(maxTTL + time.Nanosecond)
				entry.Tag = c.tag(entry)
			}
			backend.get = func(context.Context, TokenKey) (TokenEntry, bool, error) { return entry, true, nil }
			backend.delete = func(context.Context, TokenKey) error {
				t.Error("tampering must not be treated as an expiry miss")
				return nil
			}
			got, hit, err := c.cached(context.Background(), key)
			coverageCacheWantError(t, err, "invalid registry token cache entry")
			if hit || got != (TokenEntry{}) {
				t.Fatal("tampered entry exposed as a cache hit")
			}
		})
	}
}

func TestCoverageCacheBackendCancellationIsNotHidden(t *testing.T) {
	for _, backendError := range []bool{false, true} {
		t.Run(fmt.Sprintf("get-error-%v", backendError), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			backend := &coverageCacheBackend{get: func(context.Context, TokenKey) (TokenEntry, bool, error) {
				cancel()
				if backendError {
					return TokenEntry{}, false, errors.New("sensitive-details")
				}
				return TokenEntry{}, false, nil
			}}
			c := coverageCacheNewClient(t, coverageCacheNewClock(), backend)
			got, hit, err := c.cached(ctx, TokenKey{1})
			if !errors.Is(err, context.Canceled) || hit || got != (TokenEntry{}) {
				t.Fatalf("cancelled backend read = %+v, %v, %v", got, hit, err)
			}
		})
	}
	t.Run("successful write followed by cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		sets := 0
		backend := &coverageCacheBackend{set: func(_ context.Context, key TokenKey, entry TokenEntry) error {
			sets++
			if key == (TokenKey{}) || key != entry.Key || entry.Token != "received" || entry.Tag == ([32]byte{}) {
				t.Errorf("invalid stored entry: %+v", entry)
			}
			cancel()
			return nil
		}}
		c := coverageCacheNewClient(t, coverageCacheNewClock(), backend)
		c.http.Transport = coverageCacheRoundTripper(func(r *http.Request) (*http.Response, error) {
			return coverageCacheResponse(r, 200, "", `{"token":"received"}`), nil
		})
		image, err := ref.ParseNormalizedNamed("example.test/image")
		if err != nil {
			t.Fatal(err)
		}
		header, err := c.GetBearerHeader(ctx, `Bearer realm="https://example.test/token",service="Registry"`, image, "")
		if !errors.Is(err, context.Canceled) || header != "" || sets != 1 {
			t.Fatalf("cancelled write returned header=%q, error=%v, writes=%d", header, err, sets)
		}
		if err := c.lock(context.Background()); err != nil {
			t.Fatalf("cancelled write leaked client gate: %v", err)
		}
		c.unlock()
	})
}

func TestCoverageCacheInvalidationReadFailurePoisonsBackend(t *testing.T) {
	for _, mode := range []string{"backend error", "tampered entry"} {
		t.Run(mode, func(t *testing.T) {
			reads, deletes := 0, 0
			backend := &coverageCacheBackend{
				get: func(context.Context, TokenKey) (TokenEntry, bool, error) {
					reads++
					if mode == "backend error" {
						return TokenEntry{}, false, errors.New("sensitive-backend-details")
					}
					return TokenEntry{Key: TokenKey{1}, Token: "tampered"}, true, nil
				},
				delete: func(context.Context, TokenKey) error { deletes++; return nil },
			}
			c := coverageCacheNewClient(t, coverageCacheNewClock(), backend)
			want := "registry token cache operation failed"
			if mode == "tampered entry" {
				want = "invalid registry token cache entry"
			}
			err := c.InvalidateAuthorization(context.Background(), Authorization{Header: "Bearer rejected", key: TokenKey{1}})
			coverageCacheWantError(t, err, want)
			c.http.Transport = coverageCacheRoundTripper(func(*http.Request) (*http.Response, error) {
				t.Error("unsafe backend reached HTTP")
				return nil, errors.New("unexpected HTTP")
			})
			got, err := c.GetAuthorization(context.Background(), coverageCacheContainer{image: "example.test/image"}, "")
			coverageCacheWantError(t, err, "registry token cache requires replacement after failed invalidation")
			if got != (Authorization{}) || reads != 1 || deletes != 0 {
				t.Fatalf("unsafe backend reused: %+v, reads=%d, deletes=%d", got, reads, deletes)
			}
		})
	}
}

func TestCoverageCacheRouteEvictionStillInvalidatesAuthorization(t *testing.T) {
	clock := coverageCacheNewClock()
	c := coverageCacheNewClient(t, clock, nil)
	challenges, tokens := 0, 0
	c.http.Transport = coverageCacheRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/v2/" {
			challenges++
			return coverageCacheResponse(r, 401, `Bearer realm="https://example.test/token",service="Registry"`, ""), nil
		}
		tokens++
		return coverageCacheResponse(r, 200, "", fmt.Sprintf(`{"token":"token%d"}`, tokens)), nil
	})
	container := coverageCacheContainer{image: "example.test/image"}
	first, err := c.GetAuthorization(context.Background(), container, "")
	if err != nil || first.Header != "Bearer token1" {
		t.Fatalf("initial authorization = %+v, %v", first, err)
	}
	id := c.key("route-v1", container.image, "")
	for i := range defaultCapacity {
		c.remember(c.key("coverage-route", strconv.Itoa(i)), coverageCacheEntry(clock, TokenKey{9}, "metadata", time.Minute))
	}
	if _, exists := c.routes[id]; exists || c.lru.Len() != defaultCapacity || len(c.routes) != defaultCapacity {
		t.Fatal("route capacity did not evict the least-recently-used route")
	}
	if err := c.InvalidateAuthorization(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	second, err := c.GetAuthorization(context.Background(), container, "")
	if err != nil || second.Header != "Bearer token2" || challenges != 2 || tokens != 2 {
		t.Fatalf("evicted-route rejection did not refresh: %+v, %v; challenges=%d, tokens=%d", second, err, challenges, tokens)
	}
	if err := c.InvalidateAuthorization(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	current, err := c.GetAuthorization(context.Background(), container, "")
	if err != nil || current != second || tokens != 2 || challenges != 2 {
		t.Fatalf("late rejection removed refreshed token: %+v, %v", current, err)
	}
}

func TestCoverageCacheRememberReplacesAndSweepsExpiredRoutes(t *testing.T) {
	clock := coverageCacheNewClock()
	c := coverageCacheNewClient(t, clock, nil)
	id, expiredID := TokenKey{1}, TokenKey{2}
	c.remember(id, coverageCacheEntry(clock, TokenKey{3}, "old", time.Minute))
	c.remember(expiredID, coverageCacheEntry(clock, TokenKey{4}, "expiring", time.Second))
	clock.advance(time.Second)
	replacement := coverageCacheEntry(clock, TokenKey{5}, "new", time.Minute)
	c.remember(id, replacement)
	if _, exists := c.routes[expiredID]; exists {
		t.Fatal("expired route survived a route update")
	}
	if c.lru.Len() != 1 || len(c.routes) != 1 {
		t.Fatal("route replacement left duplicate metadata")
	}
	got := c.routes[id].Value.(route)
	if got.id != id || got.key != replacement.Key || !got.expires.Equal(replacement.ExpiresAt) {
		t.Fatalf("replacement route = %+v", got)
	}
}

type coverageCacheWaitingContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *coverageCacheWaitingContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

// Pause the post-acquisition check until the real context has been cancelled.
// Err always reports the underlying context's state, and Done is unchanged.
type coverageCacheAcquiredContext struct {
	context.Context
	checked chan struct{}
	resume  chan struct{}
	checks  atomic.Int32
}

func (c *coverageCacheAcquiredContext) Err() error {
	if c.checks.Add(1) == 2 {
		close(c.checked)
		<-c.resume
	}
	return c.Context.Err()
}

func TestCoverageCacheClientGateCancellationReleasesOnlyOwnSlot(t *testing.T) {
	c := coverageCacheNewClient(t, coverageCacheNewClock(), nil)
	if err := c.lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &coverageCacheWaitingContext{Context: base, waiting: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- c.lock(ctx) }()
	<-ctx.waiting
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("blocked gate cancellation = %v", err)
	}
	if len(c.gate) != 1 {
		t.Fatal("cancelled waiter released another caller's gate")
	}
	c.unlock()
	base, cancelAfterAcquire := context.WithCancel(context.Background())
	defer cancelAfterAcquire()
	acquired := &coverageCacheAcquiredContext{Context: base, checked: make(chan struct{}), resume: make(chan struct{})}
	go func() { done <- c.lock(acquired) }()
	<-acquired.checked
	cancelAfterAcquire()
	close(acquired.resume)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("post-acquisition cancellation = %v", err)
	}
	if len(c.gate) != 0 {
		t.Fatal("cancelled owner leaked gate slot")
	}
	if err := c.lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.unlock()
	if err := c.InvalidateAuthorization(base, Authorization{key: TokenKey{1}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled invalidation = %v", err)
	}
}

func TestCoverageCacheBearerValidationSeams(t *testing.T) {
	c := coverageCacheNewClient(t, coverageCacheNewClock(), &coverageCacheBackend{})
	c.http.Transport = coverageCacheRoundTripper(func(*http.Request) (*http.Response, error) {
		t.Error("invalid bearer input reached HTTP")
		return nil, errors.New("unexpected HTTP")
	})
	entry, err := c.bearer(context.Background(), &url.URL{Scheme: "https", Host: "example.test\ninvalid"}, "", "example.test/image")
	coverageCacheWantError(t, err, "invalid registry token request")
	if entry != (TokenEntry{}) {
		t.Fatal("malformed endpoint produced a token")
	}
	image, err := ref.ParseNormalizedNamed("example.test/image")
	if err != nil {
		t.Fatal(err)
	}
	header, err := c.GetBearerHeader(context.Background(), `Bearer realm="https://example.test/token",service="Registry"`, image, "bad credential")
	coverageCacheWantError(t, err, "invalid registry credentials")
	if header != "" {
		t.Fatal("invalid bearer credentials produced a header")
	}
	entry, err = parseToken([]byte(`{"token":"valid","issued_at":42}`), coverageCacheNewClock().Now())
	coverageCacheWantError(t, err, "invalid registry token issue time")
	if entry != (TokenEntry{}) {
		t.Fatal("non-string issue time produced a token")
	}
}

type coverageCacheClockFunc func() time.Time

func (f coverageCacheClockFunc) Now() time.Time { return f() }

func TestCoverageCacheBearerExpiresBeforeStorage(t *testing.T) {
	clock := coverageCacheNewClock()
	checks, writes := 0, 0
	advancing := coverageCacheClockFunc(func() time.Time {
		checks++
		if checks == 2 {
			clock.advance(time.Minute)
		}
		return clock.Now()
	})
	backend := &coverageCacheBackend{set: func(context.Context, TokenKey, TokenEntry) error { writes++; return nil }}
	c, err := NewClient(ClientOptions{Clock: advancing, Cache: backend})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.http.Transport = coverageCacheRoundTripper(func(r *http.Request) (*http.Response, error) {
		return coverageCacheResponse(r, 200, "", `{"token":"valid"}`), nil
	})
	image, err := ref.ParseNormalizedNamed("example.test/image")
	if err != nil {
		t.Fatal(err)
	}
	header, err := c.GetBearerHeader(context.Background(), `Bearer realm="https://example.test/token",service="Registry"`, image, "")
	coverageCacheWantError(t, err, "registry token expired during request")
	if header != "" || writes != 0 {
		t.Fatalf("expired token exposed or stored: header=%q, writes=%d", header, writes)
	}
}
