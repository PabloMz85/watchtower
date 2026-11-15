package auth_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PabloMz85/watchtower/internal/actions/mocks"
	"github.com/PabloMz85/watchtower/internal/registrytest"
	"github.com/PabloMz85/watchtower/pkg/registry/auth"
	ref "github.com/distribution/reference"
)

func TestCancellationDuringTokenBodyRead(t *testing.T) {
	started := make(chan struct{})
	stopped := make(chan struct{})
	server, ca := registrytest.New(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
		close(stopped)
	}))
	client, err := auth.NewClient(auth.ClientOptions{CAFile: ca})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	image, _ := ref.ParseNormalizedNamed("example.test/image")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := client.GetBearerHeader(ctx, `Bearer realm="`+server.URL+`",service="Registry"`, image, "")
		done <- err
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("body read lost cancellation: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation did not stop body read")
	}
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled response body was not closed")
	}
}

func TestUntrustedChallengeAndTokenTLSNeverReceiveCredentials(t *testing.T) {
	var tokenRequests, challengeRequests atomic.Int64
	tokenServer, _ := registrytest.New(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { tokenRequests.Add(1) }))
	challengeServer, ca := registrytest.New(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		challengeRequests.Add(1)
		w.Header().Set(auth.ChallengeHeader, `Bearer realm="`+tokenServer.URL+`",service="Registry"`)
		w.WriteHeader(401)
	}))
	image := strings.TrimPrefix(challengeServer.URL, "https://") + "/image:latest"
	c := mocks.CreateMockContainerWithDigest("id", "name", image, registrytest.NewClock().Now(), "repo@sha256:test")
	untrusted, err := auth.NewClient(auth.ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer untrusted.Close()
	if _, err := untrusted.GetToken(context.Background(), c, registrytest.Random(t)); err == nil {
		t.Fatal("untrusted challenge accepted")
	}
	if challengeRequests.Load() != 0 {
		t.Fatal("challenge was sent before TLS validation")
	}
	trustedChallenge, err := auth.NewClient(auth.ClientOptions{CAFile: ca})
	if err != nil {
		t.Fatal(err)
	}
	defer trustedChallenge.Close()
	if _, err := trustedChallenge.GetToken(context.Background(), c, registrytest.Random(t)); err == nil {
		t.Fatal("untrusted token endpoint accepted")
	}
	if challengeRequests.Load() != 1 || tokenRequests.Load() != 0 {
		t.Fatal("token credentials sent to untrusted TLS endpoint")
	}
}

func TestRedirectsNeverForwardCredentialsAcrossOriginsOrPlaintext(t *testing.T) {
	var leaked atomic.Int64
	plaintext := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Add(1) }))
	defer plaintext.Close()
	other, otherCA := registrytest.New(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Add(1) }))
	for _, target := range []string{plaintext.URL, other.URL, "https://user:password@localhost/path", "https://localhost/path#fragment"} {
		t.Run(target, func(t *testing.T) {
			server, ca := registrytest.New(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target, http.StatusFound) }))
			caData, err := os.ReadFile(otherCA)
			if err != nil {
				t.Fatal(err)
			}
			local, err := os.ReadFile(ca)
			if err != nil {
				t.Fatal(err)
			}
			bundle := filepath.Join(t.TempDir(), "bundle.pem")
			if err := os.WriteFile(bundle, append(local, caData...), 0600); err != nil {
				t.Fatal(err)
			}
			client, err := auth.NewClient(auth.ClientOptions{CAFile: bundle})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			image, _ := ref.ParseNormalizedNamed("example.test/image")
			if _, err := client.GetBearerHeader(context.Background(), `Bearer realm="`+server.URL+`",service="Registry"`, image, registrytest.Random(t)); err == nil {
				t.Fatal("unsafe redirect succeeded")
			}
		})
	}
	if leaked.Load() != 0 {
		t.Fatal("credentials forwarded outside original HTTPS origin")
	}
}

func TestSameOriginRedirectPreservesCaseAndIsBounded(t *testing.T) {
	token := registrytest.Random(t)
	credential := registrytest.Random(t)
	server, ca := registrytest.New(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/Start":
			http.Redirect(w, r, "/CaseTarget", http.StatusTemporaryRedirect)
		case "/CaseTarget":
			if r.Header.Get("Authorization") != "Basic "+credential {
				t.Error("same-origin credentials lost")
			}
			fmt.Fprintf(w, `{"token":%q}`, token)
		case "/Loop":
			http.Redirect(w, r, "/Loop", http.StatusFound)
		default:
			t.Error("case changed")
		}
	}))
	client, err := auth.NewClient(auth.ClientOptions{CAFile: ca})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	image, _ := ref.ParseNormalizedNamed("example.test/image")
	if _, err := client.GetBearerHeader(context.Background(), `Bearer realm="`+server.URL+`/Start",service="Registry"`, image, credential); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetBearerHeader(context.Background(), `Bearer realm="`+server.URL+`/Loop",service="Registry"`, image, credential); err == nil {
		t.Fatal("unbounded redirects accepted")
	}
}

func TestBoundedBodiesStatusAndTimeout(t *testing.T) {
	secret := registrytest.Random(t)
	for _, stage := range []string{"challenge", "token"} {
		for _, mode := range []string{"oversize", "timeout", "status"} {
			t.Run(stage+"/"+mode, func(t *testing.T) {
				server, ca := registrytest.New(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch mode {
					case "oversize":
						fmt.Fprint(w, strings.Repeat("x", (1<<20)+1))
					case "timeout":
						<-r.Context().Done()
					case "status":
						w.Header().Set(auth.ChallengeHeader, secret)
						w.WriteHeader(503)
						fmt.Fprint(w, secret)
					}
				}))
				client, err := auth.NewClient(auth.ClientOptions{CAFile: ca, Timeout: 100 * time.Millisecond})
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				var got string
				if stage == "challenge" {
					image := strings.TrimPrefix(server.URL, "https://") + "/image:latest"
					c := mocks.CreateMockContainerWithDigest("id", "name", image, registrytest.NewClock().Now(), "repo@sha256:test")
					got, err = client.GetToken(context.Background(), c, secret)
				} else {
					image, _ := ref.ParseNormalizedNamed("example.test/image")
					got, err = client.GetBearerHeader(context.Background(), `Bearer realm="`+server.URL+`",service="Registry"`, image, secret)
				}
				if err == nil || got != "" {
					t.Fatal("unsafe registry response accepted")
				}
				if strings.Contains(err.Error(), secret) {
					t.Fatal("body/header secret leaked")
				}
			})
		}
	}
}

func TestCAParseOnceStrictAndInstanceIsolated(t *testing.T) {
	token := registrytest.Random(t)
	server, ca := registrytest.New(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, `{"token":%q}`, token) }))
	_, otherCA := registrytest.New(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	client, err := auth.NewClient(auth.ClientOptions{CAFile: ca})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	wrong, err := auth.NewClient(auth.ClientOptions{CAFile: otherCA})
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.Close()
	original, err := os.ReadFile(ca)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ca, []byte("modified after construction"), 0600); err != nil {
		t.Fatal(err)
	}
	image, _ := ref.ParseNormalizedNamed("example.test/image")
	challenge := `Bearer realm="` + server.URL + `",service="Registry"`
	if _, err := client.GetBearerHeader(context.Background(), challenge, image, ""); err != nil {
		t.Fatal("CA unexpectedly reloaded", err)
	}
	if _, err := wrong.GetBearerHeader(context.Background(), challenge, image, ""); err == nil {
		t.Fatal("another instance's roots leaked")
	}
	for _, data := range [][]byte{append([]byte("-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n"), original...), append(append([]byte{}, original...), []byte("junk")...), append([]byte("junk\n"), original...), append(append([]byte{}, original...), []byte("-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----")...)} {
		path := filepath.Join(t.TempDir(), "invalid.pem")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if client, err := auth.NewClient(auth.ClientOptions{CAFile: path}); err == nil {
			client.Close()
			t.Fatal("partially invalid CA bundle accepted")
		}
	}
}
