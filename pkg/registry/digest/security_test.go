package digest_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/PabloMz85/watchtower/internal/actions/mocks"
	"github.com/PabloMz85/watchtower/internal/registrytest"
	"github.com/PabloMz85/watchtower/pkg/registry/auth"
	"github.com/PabloMz85/watchtower/pkg/registry/digest"
)

func TestLegacyDigestRejectsUntrustedTLS(t *testing.T) {
	var received atomic.Int64
	server, _ := registrytest.New(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.Header().Set(digest.ContentDigestHeader, "sha256:test")
	}))
	if _, err := digest.GetDigest(server.URL, registrytest.Random(t)); err == nil {
		t.Fatal("untrusted TLS accepted")
	}
	if received.Load() != 0 {
		t.Fatal("credential transmitted to untrusted server")
	}
}

func TestSharedTrustCacheAndRejectionRefresh(t *testing.T) {
	var endpoint string
	var challenges, tokens, heads atomic.Int64
	var reject atomic.Bool
	token := registrytest.Random(t)
	server, ca := registrytest.New(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v2/":
			challenges.Add(1)
			w.Header().Set(auth.ChallengeHeader, `Bearer realm="`+endpoint+`/Token",service="Registry"`)
			w.WriteHeader(401)
		case r.URL.Path == "/Token":
			tokens.Add(1)
			fmt.Fprintf(w, `{"token":%q,"expires_in":120}`, token)
		case r.Method == http.MethodHead:
			heads.Add(1)
			if reject.Load() {
				w.WriteHeader(403)
				return
			}
			if r.Header.Get("Authorization") != "Bearer "+token {
				t.Error("missing bearer header")
			}
			w.Header().Set(digest.ContentDigestHeader, "sha256:test")
		default:
			t.Error("unexpected request")
			w.WriteHeader(404)
		}
	}))
	endpoint = server.URL
	provider, err := auth.NewClient(auth.ClientOptions{CAFile: ca})
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	client, err := digest.NewClient(provider)
	if err != nil {
		t.Fatal(err)
	}
	image := strings.TrimPrefix(server.URL, "https://") + "/team/image:latest"
	c := mocks.CreateMockContainerWithDigest("id", "name", image, registrytest.NewClock().Now(), image+"@sha256:test")
	for range 2 {
		match, err := client.CompareDigest(context.Background(), c, "")
		if err != nil || !match {
			t.Fatalf("comparison: %v %v", match, err)
		}
	}
	if challenges.Load() != 1 || tokens.Load() != 1 || heads.Load() != 2 {
		t.Fatal("shared trust/cache wiring failed")
	}
	reject.Store(true)
	if _, err := client.CompareDigest(context.Background(), c, ""); err == nil {
		t.Fatal("rejected HEAD succeeded")
	}
	reject.Store(false)
	if match, err := client.CompareDigest(context.Background(), c, ""); err != nil || !match {
		t.Fatalf("refresh failed: %v", err)
	}
	if tokens.Load() != 2 {
		t.Fatal("rejected cached token was not invalidated")
	}
}
