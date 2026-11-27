package auth_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PabloMz85/watchtower/internal/actions/mocks"
	"github.com/PabloMz85/watchtower/internal/registrytest"
	"github.com/PabloMz85/watchtower/pkg/registry/auth"
	ref "github.com/distribution/reference"
)

func TestTokenResponseLifetimeValidation(t *testing.T) {
	clock := registrytest.NewClock()
	token := registrytest.Random(t)
	now := clock.Now()
	for _, test := range []struct {
		name  string
		extra string
		valid bool
		fresh time.Duration
	}{
		{"omitted", "", true, 55 * time.Second},
		{"explicit", `,"expires_in":120`, true, 115 * time.Second},
		{"issued", `,"expires_in":120,"issued_at":"` + now.Add(-30*time.Second).Format(time.RFC3339) + `"`, true, 85 * time.Second},
		{"zero", `,"expires_in":0`, false, 0},
		{"negative", `,"expires_in":-1`, false, 0},
		{"null expiry", `,"expires_in":null`, false, 0},
		{"overflow", `,"expires_in":9223372036854775808`, false, 0},
		{"exceeds maximum", `,"expires_in":86401`, false, 0},
		{"fraction", `,"expires_in":1.5`, false, 0},
		{"string expiry", `,"expires_in":"120"`, false, 0},
		{"inside margin", `,"expires_in":5`, false, 0},
		{"expired", `,"expires_in":120,"issued_at":"` + now.Add(-120*time.Second).Format(time.RFC3339) + `"`, false, 0},
		{"invalid issue time", `,"issued_at":"not-a-date"`, false, 0},
		{"future issue time", `,"issued_at":"` + now.Add(time.Second).Format(time.RFC3339) + `"`, false, 0},
		{"null issue time", `,"issued_at":null`, false, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			localClock := registrytest.NewClock()
			var calls atomic.Int64
			server, ca := registrytest.New(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				fmt.Fprintf(w, `{"token":%q%s}`, token, test.extra)
			}))
			client, err := auth.NewClient(auth.ClientOptions{Clock: localClock, CAFile: ca})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			image, _ := ref.ParseNormalizedNamed("example.test/team/image:latest")
			challenge := `Bearer realm="` + server.URL + `/token",service="Registry"`
			for range 2 {
				header, err := client.GetBearerHeader(context.Background(), challenge, image, "")
				if test.valid {
					if err != nil || header != "Bearer "+token {
						t.Fatalf("valid response failed: %v", err)
					}
				} else if err == nil || header != "" {
					t.Fatal("invalid lifetime accepted")
				}
			}
			if !test.valid {
				if calls.Load() != 2 {
					t.Fatal("invalid token was cached")
				}
				return
			}
			if calls.Load() != 1 {
				t.Fatal("fresh token not cached")
			}
			localClock.Advance(test.fresh - time.Nanosecond)
			if _, err := client.GetBearerHeader(context.Background(), challenge, image, ""); err != nil {
				t.Fatal(err)
			}
			if calls.Load() != 1 {
				t.Fatal("expired too early")
			}
			localClock.Advance(time.Nanosecond)
			_, _ = client.GetBearerHeader(context.Background(), challenge, image, "")
			// An old issued_at can make the new response expired; either way it must
			// have reached the server rather than reused the expired cache entry.
			if calls.Load() != 2 {
				t.Fatal("expiry boundary reused token")
			}
		})
	}
}

func TestMalformedTokenResponseIsNeverCached(t *testing.T) {
	token := registrytest.Random(t)
	for _, body := range []string{`{`, `{}`, `null`, `{"token":""}`, `{"token":"bad token"}`, `{"token":"bad\r\nheader"}`, `{"token":7}`, `{"token":"` + token + `"} trailing`, `{"token":"` + strings.Repeat("x", 16385) + `"}`, `{"token":"` + token + `","access_token":"` + registrytest.Random(t) + `"}`} {
		t.Run(fmt.Sprintf("body-%d", len(body)), func(t *testing.T) {
			var calls atomic.Int64
			server, ca := registrytest.New(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); fmt.Fprint(w, body) }))
			client, err := auth.NewClient(auth.ClientOptions{CAFile: ca})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			image, _ := ref.ParseNormalizedNamed("example.test/image")
			for range 2 {
				header, err := client.GetBearerHeader(context.Background(), `Bearer realm="`+server.URL+`",service="Registry"`, image, "")
				if err == nil || header != "" {
					t.Fatal("invalid response accepted")
				}
				if strings.Contains(err.Error(), body) || strings.Contains(err.Error(), token) {
					t.Fatal("response leaked in error")
				}
			}
			if calls.Load() != 2 {
				t.Fatal("malformed response cached")
			}
		})
	}
}

func TestScopeRealmServiceAndCredentialVersionIsolation(t *testing.T) {
	token := registrytest.Random(t)
	credential := registrytest.Random(t)
	var calls atomic.Int64
	server, ca := registrytest.New(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		fmt.Fprintf(w, `{"access_token":%q}`, token)
	}))
	client, err := auth.NewClient(auth.ClientOptions{CAFile: ca})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for _, test := range []struct{ image, path, service, credential string }{
		{"one.test/a", "/RealmA", "ServiceA", credential},
		{"one.test/b", "/RealmA", "ServiceA", credential},
		{"two.test/a", "/RealmA", "ServiceA", credential},
		{"one.test/a", "/RealmB", "ServiceA", credential},
		{"one.test/a", "/RealmA", "ServiceB", credential},
		{"one.test/a", "/RealmA", "ServiceA", registrytest.Random(t)},
	} {
		image, _ := ref.ParseNormalizedNamed(test.image)
		for range 2 {
			if _, err := client.GetBearerHeader(context.Background(), `Bearer realm="`+server.URL+test.path+`",service="`+test.service+`"`, image, test.credential); err != nil {
				t.Fatal(err)
			}
		}
	}
	if calls.Load() != 6 {
		t.Fatalf("scope/realm/service/identity collision: %d calls", calls.Load())
	}
}

type faultyCache struct {
	base                      auth.TokenCache
	getErr, setErr, deleteErr bool
	mutate                    func(*auth.TokenEntry)
	lastKey                   auth.TokenKey
}

func (f *faultyCache) Get(ctx context.Context, key auth.TokenKey) (auth.TokenEntry, bool, error) {
	if f.getErr {
		return auth.TokenEntry{}, false, errors.New("sensitive-backend-details")
	}
	e, ok, err := f.base.Get(ctx, key)
	if ok && f.mutate != nil {
		f.mutate(&e)
	}
	return e, ok, err
}
func (f *faultyCache) Set(ctx context.Context, key auth.TokenKey, e auth.TokenEntry) error {
	f.lastKey = key
	if f.setErr {
		return errors.New("sensitive-backend-details")
	}
	return f.base.Set(ctx, key, e)
}
func (f *faultyCache) Delete(ctx context.Context, key auth.TokenKey) error {
	if f.deleteErr {
		return errors.New("sensitive-backend-details")
	}
	return f.base.Delete(ctx, key)
}

func TestCacheErrorsAndTamperingFailClosed(t *testing.T) {
	for _, mode := range []string{"get", "set", "token", "expiry", "key", "delete"} {
		t.Run(mode, func(t *testing.T) {
			clock := registrytest.NewClock()
			base, err := auth.NewMemoryCache(clock, 2)
			if err != nil {
				t.Fatal(err)
			}
			backend := &faultyCache{base: base}
			token := registrytest.Random(t)
			credential := registrytest.Random(t)
			var endpoint string
			server, ca := registrytest.New(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v2/" {
					w.Header().Set(auth.ChallengeHeader, `Bearer realm="`+endpoint+`/token",service="Registry"`)
					w.WriteHeader(401)
					return
				}
				fmt.Fprintf(w, `{"token":%q}`, token)
			}))
			endpoint = server.URL
			client, err := auth.NewClient(auth.ClientOptions{Clock: clock, Cache: backend, CAFile: ca})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			image := strings.TrimPrefix(server.URL, "https://") + "/team/image:latest"
			c := mocks.CreateMockContainerWithDigest("id", "name", image, clock.Now(), image+"@sha256:test")
			ctx := context.Background()
			if mode == "get" {
				backend.getErr = true
			}
			if mode == "set" {
				backend.setErr = true
			}
			header, err := client.GetToken(ctx, c, credential)
			if mode == "get" || mode == "set" {
				if err == nil || header != "" {
					t.Fatal("backend failure bypassed auth")
				}
				if strings.Contains(err.Error(), "sensitive") {
					t.Fatal("backend details leaked")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			authorized, err := client.GetAuthorization(ctx, c, credential)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "token":
				backend.mutate = func(e *auth.TokenEntry) { e.Token = registrytest.Random(t) }
			case "expiry":
				backend.mutate = func(e *auth.TokenEntry) { e.ExpiresAt = e.ExpiresAt.Add(time.Second) }
			case "key":
				backend.mutate = func(e *auth.TokenEntry) { e.Key[0] ^= 1 }
			case "delete":
				backend.deleteErr = true
				if err := client.InvalidateAuthorization(ctx, authorized); err == nil {
					t.Fatal("delete error ignored")
				}
			}
			header, err = client.GetToken(ctx, c, credential)
			if err == nil || header != "" {
				t.Fatal("untrusted or rejected backend entry was reused")
			}
			if strings.Contains(err.Error(), token) || strings.Contains(err.Error(), credential) || strings.Contains(err.Error(), "sensitive") {
				t.Fatal("secret leaked in error")
			}
		})
	}
}

func TestConcurrentMissesReuseTokenAndWaitersCancel(t *testing.T) {
	token := registrytest.Random(t)
	var calls atomic.Int64
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	server, ca := registrytest.New(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		once.Do(func() { close(started) })
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		fmt.Fprintf(w, `{"token":%q}`, token)
	}))
	client, err := auth.NewClient(auth.ClientOptions{CAFile: ca})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	image, _ := ref.ParseNormalizedNamed("example.test/image")
	challenge := `Bearer realm="` + server.URL + `",service="Registry"`
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := client.GetBearerHeader(context.Background(), challenge, image, ""); err != nil {
				t.Errorf("concurrent request: %v", err)
			}
		}()
	}
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.GetBearerHeader(ctx, challenge, image, ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("waiter cancellation: %v", err)
	}
	close(release)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("misses not coalesced: %d", calls.Load())
	}
}

func TestNilAndInvalidConstructorInputs(t *testing.T) {
	var nilClock *registrytest.Clock
	var nilCache *auth.MemoryCache
	for _, options := range []auth.ClientOptions{{Clock: nilClock}, {Cache: nilCache}, {Timeout: -time.Second}, {Timeout: 6 * time.Minute}} {
		if c, err := auth.NewClient(options); err == nil {
			c.Close()
			t.Fatal("invalid constructor accepted")
		}
	}
	client, err := auth.NewClient(auth.ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.GetToken(context.Background(), nil, ""); err == nil {
		t.Fatal("nil container accepted")
	}
	if _, err := client.GetBearerHeader(context.Background(), "", nil, ""); err == nil {
		t.Fatal("nil image accepted")
	}
	image, _ := ref.ParseNormalizedNamed("example.test/image")
	for _, ctx := range []context.Context{nil} {
		if _, err := client.GetBearerHeader(ctx, `Bearer realm="https://example.test",service="Registry"`, image, ""); err == nil {
			t.Fatal("nil context accepted")
		}
	}
	var zero auth.Client
	if _, err := zero.GetBearerHeader(context.Background(), `Bearer realm="https://example.test",service="Registry"`, image, ""); err == nil {
		t.Fatal("zero client accepted")
	}
	for _, data := range []string{"", "junk", "-----BEGIN CERTIFICATE-----\nYmFk\n-----END CERTIFICATE-----"} {
		path := filepath.Join(t.TempDir(), "ca.pem")
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if c, err := auth.NewClient(auth.ClientOptions{CAFile: path}); err == nil {
			c.Close()
			t.Fatal("invalid CA accepted")
		}
	}
}
