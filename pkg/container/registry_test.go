package container

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/PabloMz85/watchtower/internal/registrytest"
	"github.com/PabloMz85/watchtower/pkg/registry/auth"
	"github.com/PabloMz85/watchtower/pkg/registry/digest"
)

func TestNewClientDefaultRegistryAndInjectedPullCache(t *testing.T) {
	var dockerRequests atomic.Int64
	dockerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		dockerRequests.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(dockerServer.Close)
	t.Setenv("DOCKER_API_VERSION", "")
	t.Setenv("DOCKER_HOST", dockerServer.URL)
	t.Setenv("DOCKER_TLS_VERIFY", "")
	t.Setenv("DOCKER_CERT_PATH", "")
	t.Setenv("DOCKER_CONFIG", t.TempDir())
	t.Setenv("REPO_USER", "")
	t.Setenv("REPO_PASS", "")
	defaults := NewClient(ClientOptions{}).(dockerClient)
	defer defaults.api.Close()
	if defaults.Registry == nil {
		t.Fatal("default constructor has no instance registry client")
	}
	var endpoint string
	var tokens, heads atomic.Int64
	token := registrytest.Random(t)
	server, ca := registrytest.New(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v2/":
			w.Header().Set(auth.ChallengeHeader, `Bearer realm="`+endpoint+`/Token",service="Registry"`)
			w.WriteHeader(401)
		case r.URL.Path == "/Token":
			tokens.Add(1)
			fmt.Fprintf(w, `{"token":%q}`, token)
		case r.Method == http.MethodHead:
			heads.Add(1)
			w.Header().Set(digest.ContentDigestHeader, "sha256:test")
		default:
			t.Error("unexpected request")
			w.WriteHeader(400)
		}
	}))
	endpoint = server.URL
	provider, err := auth.NewClient(auth.ClientOptions{CAFile: ca})
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	registry, err := digest.NewClient(provider)
	if err != nil {
		t.Fatal(err)
	}
	client := NewClient(ClientOptions{Registry: registry}).(dockerClient)
	defer client.api.Close()
	c := MockContainer(WithImageName(strings.TrimPrefix(server.URL, "https://") + "/team/image:latest"))
	c.ImageInfo().RepoDigests = []string{"repo@sha256:test"}
	for range 2 {
		if err := client.PullImage(context.Background(), c); err != nil {
			t.Fatal(err)
		}
	}
	if tokens.Load() != 1 || heads.Load() != 2 {
		t.Fatalf("pull flow did not reuse instance token: tokens=%d heads=%d", tokens.Load(), heads.Load())
	}
	if dockerRequests.Load() != 0 {
		t.Fatalf("unchanged manifest unexpectedly contacted Docker: requests=%d", dockerRequests.Load())
	}
}
