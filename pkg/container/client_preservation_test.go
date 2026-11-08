package container

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	sdkClient "github.com/moby/moby/client"
)

// Exercise real SDK decoding: Config.MacAddress is absent from the new Go type,
// so decoding fixtures straight into InspectResponse cannot detect its loss.
func TestLegacyConfiguredMACFailsClosedBeforeMutation(t *testing.T) {
	for _, version := range []string{"1.40", "1.43", "1.44", "1.51", "1.52", "1.53", "1.54", "1.56"} {
		t.Run(version, func(t *testing.T) {
			for _, running := range []bool{true, false} {
				t.Run(fmt.Sprintf("running=%t", running), func(t *testing.T) {
					var mu sync.Mutex
					var mutations []string
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						w.Header().Set("Content-Type", "application/json")
						switch {
						case r.Method == http.MethodGet && r.URL.Path == "/v"+version+"/containers/original/json":
							fmt.Fprintf(w, `{"Id":"original","Name":"/application","Image":"old-image","State":{"Running":%t},"Config":{"Image":"application:latest","MacAddress":"02:42:aa:bb:cc:dd"},"HostConfig":{"NetworkMode":"bridge"},"NetworkSettings":{"Networks":{"bridge":{"MacAddress":"02:42:aa:bb:cc:dd"}}}}`, running)
						case r.Method == http.MethodGet && r.URL.Path == "/v"+version+"/images/old-image/json":
							fmt.Fprint(w, `{"Id":"old-image","Config":{}}`)
						default:
							if r.Method != http.MethodGet && r.Method != http.MethodHead {
								mu.Lock()
								mutations = append(mutations, r.Method+" "+r.URL.Path)
								mu.Unlock()
							}
							http.Error(w, "unexpected request", http.StatusBadRequest)
						}
					}))
					defer server.Close()
					api, err := sdkClient.New(sdkClient.WithHost(server.URL), sdkClient.WithAPIVersion(version))
					if err != nil {
						t.Fatal(err)
					}
					defer api.Close()
					client := dockerClient{api: api}
					c, err := client.GetContainer("original")
					if err != nil {
						t.Fatal(err)
					}
					checkCompatibilityError := func(operation string, err error) {
						t.Helper()
						if err == nil || !strings.Contains(err.Error(), "Config.MacAddress") || !strings.Contains(err.Error(), "02:42:aa:bb:cc:dd") || !strings.Contains(err.Error(), "exclude") {
							t.Errorf("%s should explain unsupported legacy MAC and remediation, got %v", operation, err)
						}
					}
					// Update's preflight must reject it; low-level entry points must
					// also protect dependency-triggered and direct recreation paths.
					checkCompatibilityError("VerifyConfiguration", c.VerifyConfiguration())
					checkCompatibilityError("StopContainer", client.StopContainer(c, time.Millisecond))
					checkCompatibilityError("RenameContainer", client.RenameContainer(c, "/temporary"))
					_, err = client.StartContainer(c)
					checkCompatibilityError("StartContainer", err)
					mu.Lock()
					defer mu.Unlock()
					if len(mutations) != 0 {
						t.Errorf("legacy MAC protection allowed mutations: %v", mutations)
					}
				})
			}
		})
	}
}

func TestEmptyLegacyMACDoesNotBlockConfiguration(t *testing.T) {
	for _, macField := range []string{"", `,"MacAddress":""`, `,"MacAddress":null`} {
		t.Run(macField, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/v1.40/containers/original/json":
					fmt.Fprintf(w, `{"Id":"original","Image":"old-image","Config":{"Image":"application:latest"%s},"HostConfig":{},"NetworkSettings":{}}`, macField)
				case "/v1.40/images/old-image/json":
					fmt.Fprint(w, `{"Id":"old-image","Config":{}}`)
				default:
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					http.Error(w, "unexpected request", http.StatusBadRequest)
				}
			}))
			defer server.Close()
			api, err := sdkClient.New(sdkClient.WithHost(server.URL), sdkClient.WithAPIVersion("1.40"))
			if err != nil {
				t.Fatal(err)
			}
			defer api.Close()
			c, err := (dockerClient{api: api}).GetContainer("original")
			if err != nil {
				t.Fatal(err)
			}
			if err := c.VerifyConfiguration(); err != nil {
				t.Fatalf("empty legacy MAC blocked recreation: %v", err)
			}
		})
	}
}
