package container

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	dockercontainer "github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/image"
	"github.com/moby/moby/api/types/network"
	sdkClient "github.com/moby/moby/client"
)

func TestStartContainerPreservesConfiguration(t *testing.T) {
	for _, version := range []string{"1.40", "1.56"} {
		t.Run(version, func(t *testing.T) {
			var original dockercontainer.InspectResponse
			err := json.Unmarshal([]byte(`{
				"Id":"abcdef0123456789", "Name":"/application", "Image":"old-image",
				"State":{"Running":true},
				"Config":{
					"Image":"example/application:latest", "User":"image-user", "WorkingDir":"/app",
					"Entrypoint":["/entrypoint"], "Cmd":["serve"],
					"Env":["DEFAULT=old","RUNTIME=value"],
					"Labels":{"image-label":"default","runtime-label":"keep"},
					"Volumes":{"/data":{},"/cache":{}},
					"ExposedPorts":{"80/tcp":{},"8080/tcp":{},"53/udp":{}}
				},
				"HostConfig":{
					"NetworkMode":"alpha", "Binds":["/host/data:/data:rw"],
					"PortBindings":{"80/tcp":[{"HostIp":"127.0.0.1","HostPort":"8080"}]},
					"RestartPolicy":{"Name":"unless-stopped"}, "Memory":268435456,
					"CapAdd":["NET_ADMIN"]
				},
				"NetworkSettings":{"Networks":{
					"alpha":{"Aliases":["application","abcdef012345"],"IPAMConfig":{"IPv4Address":"172.20.0.10"},"DriverOpts":{"custom":"value"},"MacAddress":"02:42:ac:14:00:0a"},
					"beta":{"Aliases":["backend"],"IPAMConfig":{"IPv4Address":"172.21.0.10"}}
				}}
			}`), &original)
			if err != nil {
				t.Fatal(err)
			}
			var originalImage image.InspectResponse
			err = json.Unmarshal([]byte(`{
				"Id":"old-image","Config":{
					"User":"image-user","WorkingDir":"/app", "Entrypoint":["/entrypoint"],"Cmd":["serve"],
					"Env":["DEFAULT=old"], "Labels":{"image-label":"default"},
					"Volumes":{"/data":{}},"ExposedPorts":{"80/tcp":{},"53/udp":{}}
				}
			}`), &originalImage)
			if err != nil {
				t.Fatal(err)
			}
			wantHost := *original.HostConfig
			wantEndpoints := make(map[string]*network.EndpointSettings)
			for name, endpoint := range original.NetworkSettings.Networks {
				wantEndpoints[name] = endpoint.Copy()
			}
			wantEndpoints["alpha"].Aliases = []string{"application"}

			var created dockercontainer.CreateRequest
			connected := make(map[string]*network.EndpointSettings)
			var disconnected []string
			var requests []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests = append(requests, r.Method+" "+r.URL.Path)
				w.Header().Set("Content-Type", "application/json")
				path := strings.TrimPrefix(r.URL.Path, "/v"+version)
				switch {
				case r.Method == http.MethodPost && path == "/containers/create":
					if r.URL.Query().Get("name") != "/application" {
						t.Errorf("create name = %q", r.URL.Query().Get("name"))
					}
					if err := json.NewDecoder(r.Body).Decode(&created); err != nil {
						t.Error(err)
					}
					w.WriteHeader(http.StatusCreated)
					fmt.Fprint(w, `{"Id":"new-container"}`)
				case r.Method == http.MethodPost && strings.HasSuffix(path, "/disconnect"):
					var body network.DisconnectRequest
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
					}
					if body.Container != "new-container" || !body.Force {
						t.Errorf("disconnect options = %+v", body)
					}
					disconnected = append(disconnected, strings.TrimSuffix(strings.TrimPrefix(path, "/networks/"), "/disconnect"))
					w.WriteHeader(http.StatusNoContent)
				case r.Method == http.MethodPost && strings.HasSuffix(path, "/connect"):
					var body network.ConnectRequest
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
					}
					if body.Container != "new-container" {
						t.Errorf("connect container = %q", body.Container)
					}
					connected[strings.TrimSuffix(strings.TrimPrefix(path, "/networks/"), "/connect")] = body.EndpointConfig
					w.WriteHeader(http.StatusNoContent)
				case r.Method == http.MethodPost && path == "/containers/new-container/start":
					w.WriteHeader(http.StatusNoContent)
				default:
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					http.Error(w, "unexpected request", http.StatusBadRequest)
				}
			}))
			defer server.Close()
			api, err := sdkClient.New(sdkClient.WithHost(server.URL), sdkClient.WithAPIVersion(version))
			if err != nil {
				t.Fatal(err)
			}
			defer api.Close()
			id, err := (dockerClient{api: api}).StartContainer(NewContainer(&original, &originalImage))
			if err != nil || id != "new-container" {
				t.Fatalf("StartContainer = %q, %v", id, err)
			}
			if created.Config == nil || created.HostConfig == nil || created.NetworkingConfig == nil {
				t.Fatalf("incomplete create request: %+v", created)
			}
			wantConfig := &dockercontainer.Config{
				Image: "example/application:latest", Env: []string{"RUNTIME=value"},
				Labels: map[string]string{"runtime-label": "keep"}, Volumes: map[string]struct{}{"/cache": {}},
				ExposedPorts: network.PortSet{network.MustParsePort("80/tcp"): {}, network.MustParsePort("8080/tcp"): {}},
			}
			if !reflect.DeepEqual(created.Config, wantConfig) {
				t.Errorf("create config = %+v, want %+v", created.Config, wantConfig)
			}
			// The SDK normalizes capability names, but must preserve their meaning.
			wantHost.CapAdd = []string{"CAP_NET_ADMIN"}
			if !reflect.DeepEqual(*created.HostConfig, wantHost) {
				t.Errorf("host config = %+v, want %+v", *created.HostConfig, wantHost)
			}
			if len(created.NetworkingConfig.EndpointsConfig) != 1 || len(disconnected) != 1 {
				t.Fatalf("expected one initial network and disconnect, got %+v, %v", created.NetworkingConfig, disconnected)
			}
			for name, endpoint := range created.NetworkingConfig.EndpointsConfig {
				if name != disconnected[0] || !reflect.DeepEqual(endpoint, wantEndpoints[name]) {
					t.Errorf("initial endpoint %s = %+v, disconnect=%v", name, endpoint, disconnected)
				}
			}
			if !reflect.DeepEqual(connected, wantEndpoints) {
				t.Errorf("reconnected endpoints = %+v, want %+v", connected, wantEndpoints)
			}
			if len(requests) != 5 || requests[len(requests)-1] != "POST /v"+version+"/containers/new-container/start" {
				t.Errorf("unexpected recreate sequence: %v", requests)
			}
		})
	}
}

func TestRemoveImagePreservesAncestors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/v1.40/images/old-image" || r.URL.Query().Get("force") != "1" || r.URL.Query().Get("noprune") != "1" {
			t.Errorf("unexpected removal request: %s %s", r.Method, r.URL)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `[{"Deleted":"old-image"}]`)
	}))
	defer server.Close()
	api, err := sdkClient.New(sdkClient.WithHost(server.URL), sdkClient.WithAPIVersion("1.40"))
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	if err := (dockerClient{api: api}).RemoveImageByID("old-image"); err != nil {
		t.Fatal(err)
	}
}

func TestHasNewImageUsesInspectResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1.40/images/example/application:latest/json" {
			t.Errorf("unexpected inspect request: %s %s", r.Method, r.URL)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"Id":"new-image"}`)
	}))
	defer server.Close()
	api, err := sdkClient.New(sdkClient.WithHost(server.URL), sdkClient.WithAPIVersion("1.40"))
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	c := NewContainer(&dockercontainer.InspectResponse{
		ID: "container", Name: "/application", Image: "old-image",
		Config: &dockercontainer.Config{Image: "example/application:latest"},
	}, &image.InspectResponse{ID: "old-image"})
	stale, id, err := (dockerClient{api: api}).HasNewImage(context.Background(), c)
	if err != nil || !stale || id != "new-image" {
		t.Fatalf("HasNewImage = %v, %q, %v", stale, id, err)
	}
}
