package container

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	sdkClient "github.com/moby/moby/client"

	"github.com/containrrr/watchtower/pkg/filters"
)

func TestNewClientNegotiatesDaemonAPI(t *testing.T) {
	t.Setenv("DOCKER_API_VERSION", "")
	t.Setenv("DOCKER_TLS_VERIFY", "")
	t.Setenv("DOCKER_CERT_PATH", "")
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		w.Header().Set("API-Version", "1.40")
		if r.URL.Path == "/_ping" {
			return
		}
		if r.URL.Path != "/v1.40/containers/json" {
			http.Error(w, fmt.Sprintf("unexpected API request: %s", r.URL.Path), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, "[]")
	}))
	defer server.Close()
	t.Setenv("DOCKER_HOST", server.URL)

	containers, err := NewClient(ClientOptions{}).ListContainers(filters.NoFilter)
	if err != nil {
		t.Fatalf("ListContainers must negotiate daemon API 1.40: %v (requests: %v)", err, requests)
	}
	if len(containers) != 0 {
		t.Fatalf("expected no containers, got %d", len(containers))
	}
	if len(requests) < 2 || requests[0] != "HEAD /_ping" || requests[len(requests)-1] != "GET /v1.40/containers/json" {
		t.Fatalf("expected ping then negotiated API request, got %v", requests)
	}
}

func TestNewClientAPIVersionSelection(t *testing.T) {
	for _, tc := range []struct {
		name, daemonVersion, override, wantVersion string
	}{
		{name: "negotiate down", daemonVersion: "1.44", wantVersion: "1.44"},
		{name: "current daemon", daemonVersion: "1.56", wantVersion: "1.56"},
		{name: "newer daemon capped at client maximum", daemonVersion: "1.99", wantVersion: sdkClient.MaxAPIVersion},
		{name: "explicit pin", daemonVersion: "1.56", override: "1.41", wantVersion: "1.41"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DOCKER_API_VERSION", tc.override)
			t.Setenv("DOCKER_TLS_VERIFY", "")
			t.Setenv("DOCKER_CERT_PATH", "")
			var requests []string
			path := "/v" + tc.wantVersion + "/containers/json"
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests = append(requests, r.Method+" "+r.URL.Path)
				w.Header().Set("API-Version", tc.daemonVersion)
				if r.URL.Path == "/_ping" {
					return
				}
				if r.URL.Path != path {
					http.Error(w, "unexpected API version", http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, "[]")
			}))
			defer server.Close()
			t.Setenv("DOCKER_HOST", server.URL)
			client := NewClient(ClientOptions{}).(dockerClient)
			defer client.api.Close()
			// A successful negotiation is cached, not repeated for every request.
			for range 2 {
				if _, err := client.ListContainers(filters.NoFilter); err != nil {
					t.Fatalf("ListContainers: %v (requests: %v)", err, requests)
				}
			}
			want := []string{"GET " + path, "GET " + path}
			if tc.override == "" {
				want = append([]string{"HEAD /_ping"}, want...)
			}
			if !reflect.DeepEqual(requests, want) {
				t.Fatalf("requests = %v, want %v", requests, want)
			}
		})
	}
}

func TestNewClientDaemonFailure(t *testing.T) {
	t.Setenv("DOCKER_API_VERSION", "")
	t.Setenv("DOCKER_TLS_VERIFY", "")
	t.Setenv("DOCKER_CERT_PATH", "")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("API-Version", "1.40")
		if r.URL.Path == "/_ping" {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"message":"daemon unavailable"}`)
	}))
	defer server.Close()
	t.Setenv("DOCKER_HOST", server.URL)
	client := NewClient(ClientOptions{}).(dockerClient)
	defer client.api.Close()
	containers, err := client.ListContainers(filters.NoFilter)
	if err == nil || !strings.Contains(err.Error(), "daemon unavailable") {
		t.Fatalf("expected daemon failure, got containers=%v, err=%v", containers, err)
	}
	if containers != nil {
		t.Fatalf("failed listing must return nil containers, got %v", containers)
	}
}

func TestNewClientConnectionFailure(t *testing.T) {
	t.Setenv("DOCKER_API_VERSION", "")
	t.Setenv("DOCKER_TLS_VERIFY", "")
	t.Setenv("DOCKER_CERT_PATH", "")
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.Close()
	t.Setenv("DOCKER_HOST", server.URL)
	client := NewClient(ClientOptions{}).(dockerClient)
	defer client.api.Close()
	if containers, err := client.ListContainers(filters.NoFilter); err == nil || containers != nil {
		t.Fatalf("expected connection failure and nil containers, got %v, %v", containers, err)
	}
}
