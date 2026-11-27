package auth_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PabloMz85/watchtower/internal/actions/mocks"
	"github.com/PabloMz85/watchtower/internal/registrytest"
	"github.com/PabloMz85/watchtower/pkg/registry/auth"
)

func TestInstanceTokenCacheIdentityAndDefaultExpiry(t *testing.T) {
	clock := registrytest.NewClock()
	var challengeCalls, tokenCalls atomic.Int64
	token := registrytest.Random(t)
	var endpoint string
	server, ca := registrytest.New(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/" {
			challengeCalls.Add(1)
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+endpoint+`/CaseToken",service="CaseService"`)
			w.WriteHeader(401)
			return
		}
		if r.URL.Path != "/CaseToken" || r.URL.Query().Get("service") != "CaseService" {
			t.Errorf("case changed in request")
			w.WriteHeader(400)
			return
		}
		tokenCalls.Add(1)
		fmt.Fprintf(w, `{"token":%q}`, token)
	}))
	endpoint = server.URL
	client, err := auth.NewClient(auth.ClientOptions{Clock: clock, CAFile: ca})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	image := strings.TrimPrefix(server.URL, "https://") + "/team/image:latest"
	c := mocks.CreateMockContainerWithDigest("id", "name", image, clock.Now(), image+"@sha256:test")
	ctx := context.Background()
	a, b := registrytest.Random(t), registrytest.Random(t)
	for _, credential := range []string{a, b, "", a, b, ""} {
		header, err := client.GetToken(ctx, c, credential)
		if err != nil {
			t.Fatal(err)
		}
		if header != "Bearer "+token {
			t.Fatal("wrong token")
		}
	}
	if tokenCalls.Load() != 3 || challengeCalls.Load() != 3 {
		t.Fatalf("identity cache calls: token=%d challenge=%d", tokenCalls.Load(), challengeCalls.Load())
	}
	clock.Advance(54 * time.Second)
	if _, err := client.GetToken(ctx, c, a); err != nil {
		t.Fatal(err)
	}
	if tokenCalls.Load() != 3 {
		t.Fatal("expired before margin")
	}
	clock.Advance(time.Second)
	if _, err := client.GetToken(ctx, c, a); err != nil {
		t.Fatal(err)
	}
	if tokenCalls.Load() != 4 {
		t.Fatal("omitted expiry must refresh at 60s minus 5s margin")
	}
}

func TestMemoryCacheBoundedExpiryAndCancellation(t *testing.T) {
	clock := registrytest.NewClock()
	cache, err := auth.NewMemoryCache(clock, 2)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	keys := []auth.TokenKey{{1}, {2}, {3}}
	for _, key := range keys {
		if err := cache.Set(ctx, key, auth.TokenEntry{Key: key, Token: registrytest.Random(t), ExpiresAt: clock.Now().Add(time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok, err := cache.Get(ctx, keys[0]); err != nil || ok {
		t.Fatal("oldest entry not evicted")
	}
	clock.Advance(time.Minute)
	if _, ok, err := cache.Get(ctx, keys[2]); err != nil || ok {
		t.Fatal("expired entry accepted")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := cache.Delete(cancelled, keys[1]); err != context.Canceled {
		t.Fatalf("cancellation lost: %v", err)
	}
	if _, err := auth.NewMemoryCache(nil, 2); err == nil {
		t.Fatal("nil clock accepted")
	}
	if _, err := auth.NewMemoryCache(clock, 0); err == nil {
		t.Fatal("unbounded capacity accepted")
	}
}
