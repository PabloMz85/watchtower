package digest_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PabloMz85/watchtower/internal/actions/mocks"
	"github.com/PabloMz85/watchtower/internal/meta"
	"github.com/PabloMz85/watchtower/internal/registrytest"
	"github.com/PabloMz85/watchtower/pkg/container"
	"github.com/PabloMz85/watchtower/pkg/registry/auth"
	"github.com/PabloMz85/watchtower/pkg/registry/digest"
	wt "github.com/PabloMz85/watchtower/pkg/types"
)

func coverageDigestClient(t *testing.T, options auth.ClientOptions) *digest.Client {
	t.Helper()
	provider, err := auth.NewClient(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(provider.Close)
	client, err := digest.NewClient(provider)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func coverageDigestError(t *testing.T, value string, err error, want string) {
	t.Helper()
	if value != "" || err == nil || err.Error() != want {
		t.Fatalf("result = %q, %v; want empty result and %q", value, err, want)
	}
}

func TestCoverageDigestRequiredInputs(t *testing.T) {
	if client, err := digest.NewClient(nil); client != nil || err == nil || err.Error() != "registry auth client is required" {
		t.Fatalf("nil provider = %v, %v", client, err)
	}
	valid := coverageDigestClient(t, auth.ClientOptions{})
	for _, tc := range []struct {
		name   string
		client *digest.Client
		ctx    context.Context
	}{
		{"nil client", nil, context.Background()},
		{"zero client", &digest.Client{}, context.Background()},
		{"nil context", valid, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value, err := tc.client.GetDigest(tc.ctx, "https://127.0.0.1/", "Bearer fixture")
			coverageDigestError(t, value, err, "registry client and context are required")
			match, err := tc.client.CompareDigest(tc.ctx, nil, "")
			if match || err == nil || err.Error() != "registry client and context are required" {
				t.Fatalf("comparison = %v, %v", match, err)
			}
		})
	}
	var typedNil *container.Container
	for _, c := range []wt.Container{nil, typedNil, mocks.CreateMockContainerWithImageInfoP("id", "name", "local/image:tag", registrytest.NewClock().Now(), nil)} {
		match, err := valid.CompareDigest(context.Background(), c, "")
		if match || err == nil || err.Error() != "container image info missing" {
			t.Fatalf("missing image comparison = %v, %v", match, err)
		}
	}
	invalid := mocks.CreateMockContainer("id", "name", "INVALID REFERENCE:tag", registrytest.NewClock().Now())
	match, err := valid.CompareDigest(context.Background(), invalid, "")
	if match || err == nil || err.Error() != "invalid registry manifest reference" {
		t.Fatalf("invalid reference comparison = %v, %v", match, err)
	}
}

func TestCoverageDigestRejectsInvalidTokensBeforeHTTP(t *testing.T) {
	var received atomic.Int64
	server, ca := registrytest.New(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.Header().Set(digest.ContentDigestHeader, "sha256:fixture")
	}))
	client := coverageDigestClient(t, auth.ClientOptions{CAFile: ca})
	for _, tc := range []struct{ name, token string }{
		{"empty", ""},
		{"oversized", strings.Repeat("x", 32769)},
		{"carriage return", "Bearer x\ry"},
		{"newline", "Bearer x\ny"},
		{"NUL", "Bearer x\x00y"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value, err := client.GetDigest(context.Background(), server.URL, tc.token)
			coverageDigestError(t, value, err, "could not fetch valid registry token")
		})
	}
	value, err := client.GetDigest(context.Background(), "https://[malformed", "Bearer fixture")
	coverageDigestError(t, value, err, "invalid registry manifest endpoint")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	value, err = client.GetDigest(ctx, server.URL, "Bearer fixture")
	if value != "" || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled request = %q, %v", value, err)
	}
	if received.Load() != 0 {
		t.Fatalf("invalid input reached server %d times", received.Load())
	}
}

func TestCoverageDigestHTTPContract(t *testing.T) {
	token := "Bearer " + registrytest.Random(t)
	wantAccept := []string{
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.docker.distribution.manifest.v1+json",
		"application/vnd.oci.image.index.v1+json",
	}
	server, ca := registrytest.New(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead || r.URL.Path != "/v2/team/image/manifests/tag" || r.URL.RawQuery != "fixture=1" {
			t.Errorf("unexpected manifest request: %s %s", r.Method, r.URL.RequestURI())
		}
		if r.Header.Get("User-Agent") != meta.UserAgent || r.Header.Get("Authorization") != token {
			t.Error("manifest user-agent or authorization mismatch")
		}
		// HTTP/1 may combine repeated header fields; retain the value order.
		if got := strings.Split(strings.Join(r.Header.Values("Accept"), ","), ","); !reflect.DeepEqual(got, wantAccept) {
			t.Errorf("Accept values = %q; want %q", got, wantAccept)
		}
		w.Header().Set(digest.ContentDigestHeader, "sha256:fixture")
		w.WriteHeader(http.StatusOK)
	}))
	client := coverageDigestClient(t, auth.ClientOptions{CAFile: ca})
	value, err := client.GetDigest(context.Background(), server.URL+"/v2/team/image/manifests/tag?fixture=1", token)
	if err != nil || value != "sha256:fixture" {
		t.Fatalf("manifest digest = %q, %v", value, err)
	}
}

func TestCoverageDigestResponseValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		digest string
		want   string
	}{
		{"missing", 200, "", "registry manifest digest is missing or invalid"},
		{"oversized", 200, strings.Repeat("d", 1025), "registry manifest digest is missing or invalid"},
		{"limit accepted", 200, strings.Repeat("d", 1024), ""},
		{"unauthorized", 401, "sha256:ignored", ""},
		{"forbidden", 403, "sha256:ignored", ""},
		{"no content", 204, "sha256:ignored", ""},
		{"unavailable", 503, "sha256:ignored", ""},
		// net/http rejects NUL in wire headers before digest validation runs.
		{"invalid wire header", 200, "sha256:a\x00b", "registry HTTPS request failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, ca := registrytest.New(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(digest.ContentDigestHeader, tc.digest)
				w.Header().Set("X-Fixture-Private", "must-not-appear-in-errors")
				w.WriteHeader(tc.status)
			}))
			client := coverageDigestClient(t, auth.ClientOptions{CAFile: ca})
			value, err := client.GetDigest(context.Background(), server.URL, "Bearer fixture")
			if tc.want != "" {
				coverageDigestError(t, value, err, tc.want)
			} else if tc.status != http.StatusOK {
				var status *auth.StatusError
				if value != "" || !errors.As(err, &status) || status.Code != tc.status || err.Error() != fmt.Sprintf("registry HTTP status %d", tc.status) {
					t.Fatalf("status result = %q, %v; want status %d", value, err, tc.status)
				}
			} else if err != nil || value != tc.digest {
				t.Fatalf("bounded digest result = %q, %v", value, err)
			}
		})
	}
}

func TestCoverageDigestInFlightCancellation(t *testing.T) {
	started := make(chan struct{})
	stopped := make(chan struct{})
	server, ca := registrytest.New(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(stopped)
	}))
	client := coverageDigestClient(t, auth.ClientOptions{CAFile: ca})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		value, err := client.GetDigest(ctx, server.URL, "Bearer fixture")
		if value != "" {
			err = fmt.Errorf("canceled request returned a digest")
		}
		result <- err
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("manifest request did not reach local server")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("in-flight cancellation = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("manifest request did not cancel")
	}
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("server request context did not cancel")
	}
}

func TestCoverageDigestTransformAuthFallbackAndPassThrough(t *testing.T) {
	raw := []byte("{\"username\":\"user\",\"password\":\"\uffff\"}")
	standard := base64.StdEncoding.EncodeToString(raw)
	if !strings.ContainsAny(standard, "+/") {
		t.Fatal("fixture must require the standard base64 alphabet")
	}
	want := base64.StdEncoding.EncodeToString([]byte("user:\uffff"))
	if got := digest.TransformAuth(standard); got != want {
		t.Fatal("standard-base64 JSON credentials were not converted")
	}
	for _, input := range []string{
		"", "not-base64!", base64.StdEncoding.EncodeToString([]byte("not JSON")),
		base64.StdEncoding.EncodeToString([]byte(`{"username":"user"}`)),
		base64.StdEncoding.EncodeToString([]byte(`{"password":"pass"}`)),
		base64.StdEncoding.EncodeToString([]byte("fixture-user:fixture-pass")),
	} {
		if got := digest.TransformAuth(input); got != input {
			t.Fatal("incomplete or non-JSON credentials were not preserved")
		}
	}
}

type coverageDigestRejectDelete struct {
	auth.TokenCache
	deletes atomic.Int64
}

func (c *coverageDigestRejectDelete) Delete(ctx context.Context, key auth.TokenKey) error {
	c.deletes.Add(1)
	return errors.New("fixture backend detail must not escape")
}

func TestCoverageDigestComparisonAndInvalidationError(t *testing.T) {
	clock := registrytest.NewClock()
	memory, err := auth.NewMemoryCache(clock, 4)
	if err != nil {
		t.Fatal(err)
	}
	cache := &coverageDigestRejectDelete{TokenCache: memory}
	var endpoint string
	var reject atomic.Bool
	var heads atomic.Int64
	bearer := registrytest.Random(t)
	server, ca := registrytest.New(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/":
			w.Header().Set(auth.ChallengeHeader, `Bearer realm="`+endpoint+`/token",service="Fixture"`)
			w.WriteHeader(http.StatusUnauthorized)
		case "/token":
			fmt.Fprintf(w, `{"token":%q,"expires_in":120}`, bearer)
		case "/v2/team/image/manifests/tag":
			heads.Add(1)
			if r.Method != http.MethodHead || r.Header.Get("Authorization") != "Bearer "+bearer {
				t.Error("invalid authenticated manifest request")
			}
			if reject.Load() {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set(digest.ContentDigestHeader, "sha256:remote")
		default:
			t.Error("unexpected registry route")
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	endpoint = server.URL
	client := coverageDigestClient(t, auth.ClientOptions{CAFile: ca, Clock: clock, Cache: cache})
	image := strings.TrimPrefix(server.URL, "https://") + "/team/image:tag"
	c := mocks.CreateMockContainer("id", "name", image, clock.Now())
	for _, tc := range []struct {
		name  string
		local []string
		match bool
	}{
		{"empty", nil, false},
		{"malformed and unequal", []string{"sha256:remote", image + "@sha256:other"}, false},
		{"later match", []string{image + "@sha256:other", image + "@sha256:remote"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c.ImageInfo().RepoDigests = tc.local
			match, err := client.CompareDigest(context.Background(), c, "")
			if err != nil || match != tc.match {
				t.Fatalf("comparison = %v, %v; want match %v", match, err, tc.match)
			}
		})
	}
	reject.Store(true)
	match, err := client.CompareDigest(context.Background(), c, "")
	if match || err == nil || err.Error() != "registry token cache operation failed" {
		t.Fatalf("invalidation error = %v, %v", match, err)
	}
	if cache.deletes.Load() != 1 || heads.Load() != 4 {
		t.Fatalf("delete calls = %d, manifest calls = %d; want 1 and 4 without automatic retry", cache.deletes.Load(), heads.Load())
	}
}

func TestCoverageDigestBasicCredentialsReachOnlyTrustedManifest(t *testing.T) {
	credentials := base64.StdEncoding.EncodeToString([]byte("fixture-user:fixture-pass"))
	var heads atomic.Int64
	server, ca := registrytest.New(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/":
			if r.Header.Get("Authorization") != "" {
				t.Error("challenge request unexpectedly included credentials")
			}
			w.Header().Set(auth.ChallengeHeader, `Basic realm="Fixture"`)
			w.WriteHeader(http.StatusUnauthorized)
		case "/v2/team/image/manifests/tag":
			heads.Add(1)
			if r.Method != http.MethodHead || r.Header.Get("Authorization") != "Basic "+credentials {
				t.Error("Basic credentials did not reach the trusted manifest endpoint")
			}
			w.Header().Set(digest.ContentDigestHeader, "sha256:fixture")
		default:
			t.Error("unexpected Basic registry route")
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	client := coverageDigestClient(t, auth.ClientOptions{CAFile: ca})
	image := strings.TrimPrefix(server.URL, "https://") + "/team/image:tag"
	c := mocks.CreateMockContainerWithDigest("id", "name", image, registrytest.NewClock().Now(), image+"@sha256:fixture")
	match, err := client.CompareDigest(context.Background(), c, "")
	if match || err == nil || err.Error() != "no valid registry credentials available" || heads.Load() != 0 {
		t.Fatalf("missing Basic credentials = %v, %v; manifest calls %d", match, err, heads.Load())
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(`{"username":"fixture-user","password":"fixture-pass"}`))
	match, err = client.CompareDigest(context.Background(), c, encoded)
	if err != nil || !match || heads.Load() != 1 {
		t.Fatalf("Basic comparison = %v, %v; manifest calls %d", match, err, heads.Load())
	}
}
