package mocks

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	dc "github.com/moby/moby/api/types/container"
	di "github.com/moby/moby/api/types/image"
	"github.com/moby/moby/client"
	O "github.com/onsi/gomega"
)

// The helpers use Gomega's process-global instance, including a response handler
// captured at package initialization. Keep tests serial and restore that instance.
func useHTTPAssertions(t *testing.T) {
	t.Helper()
	instance, ok := O.Default.(*O.WithT)
	if !ok {
		t.Fatal("unexpected default Gomega implementation")
	}
	saved := *instance
	O.RegisterTestingT(t)
	t.Cleanup(func() { *instance = saved })
}

func readFixture(t *testing.T, path string, result any) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, result); err != nil {
		t.Fatalf("invalid fixture %s: %v", path, err)
	}
	return data
}

func serveContract(handler http.HandlerFunc, method, path string) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	handler(response, httptest.NewRequest(method, path, nil))
	return response
}

func decodeResponse(t *testing.T, response *httptest.ResponseRecorder, status int, dst any) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status = %d, want %d", response.Code, status)
	}
	if err := json.Unmarshal(response.Body.Bytes(), dst); err != nil {
		t.Fatalf("invalid response JSON: %v", err)
	}
}

func TestFixtureReferencesResolveExistingContainerMetadata(t *testing.T) {
	t.Chdir("..")
	for _, ref := range []*ContainerRef{&Watchtower, &Stopped, &Running, &Restarting, &NetConsumerOK, &NetConsumerInvalidSupplier, &netSupplierOK} {
		t.Run(ref.name, func(t *testing.T) {
			path, err := ref.getContainerFile()
			if err != nil {
				t.Fatal(err)
			}
			if path != "./mocks/data/container_"+ref.name+".json" || ref.ContainerID() != ref.id {
				t.Fatal("reference lost fixture naming or container identity")
			}
			var info dc.InspectResponse
			readFixture(t, path, &info)
			if info.ID != string(ref.ContainerID()) || info.Image != string(ref.image.id) || info.Name == "" || info.Config == nil || info.HostConfig == nil || info.State == nil {
				t.Fatal("container fixture does not satisfy its reference's structural inspect contract")
			}
		})
	}
	override := ContainerRef{name: "unused-name", file: "running", id: Running.id}
	path, err := override.getContainerFile()
	if err != nil || path != "./mocks/data/container_running.json" {
		t.Fatal("explicit fixture file must take precedence over reference name")
	}
	absent := ContainerRef{name: "does-not-exist"}
	path, err = absent.getContainerFile()
	if !os.IsNotExist(err) || !strings.HasSuffix(path, "container_does-not-exist.json") {
		t.Fatal("missing container fixture must return its attempted path and a filesystem error")
	}
	if got := NetConsumerOK.image.getFileName(); got != "./mocks/data/image_net_consumer.json" {
		t.Fatalf("image fixture path = %s", got)
	}
}

func TestJSONFileResponsesPreserveFixtureBytesStatusAndHeaders(t *testing.T) {
	useHTTPAssertions(t)
	t.Chdir("..")
	path := "./mocks/data/container_running.json"
	var info dc.InspectResponse
	want := readFixture(t, path, &info)
	handler := RespondWithJSONFile(path, http.StatusAccepted, http.Header{"Content-Type": {"application/json"}, "X-Fixture": {"running"}})
	response := serveContract(handler, "GET", "/unused")
	if response.Code != http.StatusAccepted || !reflect.DeepEqual(response.Body.Bytes(), want) || response.Header().Get("X-Fixture") != "running" || response.Header().Get("Content-Type") != "application/json" {
		t.Fatal("file response must retain exact producer bytes, supplied status, and optional headers")
	}
	missingPath := filepath.Join(t.TempDir(), "missing.json")
	if data, err := getMockJSONFile(missingPath); err == nil || data != nil || !strings.Contains(err.Error(), missingPath) {
		t.Fatal("missing JSON file must return contextual error without content")
	}
	if handler, err := respondWithJSONFile(missingPath, http.StatusOK); err == nil || handler != nil {
		t.Fatal("error-returning response factory must not create a handler for an unreadable file")
	}
}

func TestContainerAndImageHandlersRoundTripDockerDTOs(t *testing.T) {
	useHTTPAssertions(t)
	t.Chdir("..")
	var container dc.InspectResponse
	var image di.InspectResponse
	readFixture(t, "./mocks/data/container_net_consumer.json", &container)
	readFixture(t, "./mocks/data/image_net_consumer.json", &image)
	if container.Image != image.ID {
		t.Fatal("producer container and image fixtures must agree")
	}
	for _, prefix := range []string{"", "/v1.47"} {
		var gotContainer dc.InspectResponse
		decodeResponse(t, serveContract(GetContainerHandler(container.ID, &container), "GET", prefix+"/containers/"+container.ID+"/json"), http.StatusOK, &gotContainer)
		if !reflect.DeepEqual(gotContainer, container) {
			t.Fatal("container handler did not preserve the Docker inspection DTO")
		}
		var gotImage di.InspectResponse
		decodeResponse(t, serveContract(GetImageHandler(&image), "GET", prefix+"/images/"+image.ID+"/json"), http.StatusOK, &gotImage)
		if !reflect.DeepEqual(gotImage, image) {
			t.Fatal("image handler did not preserve the Docker inspection DTO")
		}
	}
	missing := serveContract(GetContainerHandler("missing", nil), "GET", "/v1.47/containers/missing/json")
	// Error-message JSON has a separately reported production bug; do not bless it.
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing container status = %d", missing.Code)
	}
}

func TestContainerHandlersExpandNetworkReferencesInLookupOrder(t *testing.T) {
	useHTTPAssertions(t)
	t.Chdir("..")
	for _, tc := range []struct {
		name    string
		ref     *ContainerRef
		missing bool
	}{
		{"available supplier", &NetConsumerOK, false},
		{"missing supplier", &NetConsumerInvalidSupplier, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handlers := GetContainerHandlers(tc.ref)
			if len(handlers) != 3 {
				t.Fatalf("got %d handlers, want owner, referenced supplier, owner image", len(handlers))
			}
			var consumer dc.InspectResponse
			decodeResponse(t, serveContract(handlers[0], "GET", "/v1.47/containers/"+string(tc.ref.id)+"/json"), http.StatusOK, &consumer)
			if consumer.ID != string(tc.ref.id) {
				t.Fatal("first handler must inspect the owning container")
			}
			supplierRef := tc.ref.references[0]
			supplierResponse := serveContract(handlers[1], "GET", "/v1.47/containers/"+string(supplierRef.id)+"/json")
			if tc.missing {
				if supplierResponse.Code != http.StatusNotFound || consumer.HostConfig.NetworkMode.ConnectedContainer() != NetSupplierNotFoundID {
					t.Fatal("missing supplier must correspond to the consumer's network reference and return 404")
				}
			} else {
				var supplier dc.InspectResponse
				decodeResponse(t, supplierResponse, http.StatusOK, &supplier)
				if supplier.ID != string(supplierRef.id) || supplier.Name != NetSupplierContainerName || consumer.HostConfig.NetworkMode.ConnectedContainer() != supplier.ID {
					t.Fatal("supplier response must resolve the consumer's container-network dependency")
				}
			}
			var image di.InspectResponse
			decodeResponse(t, serveContract(handlers[2], "GET", "/v1.47/images/"+string(tc.ref.image.id)+"/json"), http.StatusOK, &image)
			if image.ID != consumer.Image {
				t.Fatal("last handler must inspect the owning container's image, not the supplier's")
			}
		})
	}
	if len(GetContainerHandlers()) != 0 {
		t.Fatal("empty reference input must not create requests")
	}
}

func TestListContainersFiltersFixtureStatusesWithoutDuplicates(t *testing.T) {
	useHTTPAssertions(t)
	t.Chdir("..")
	var all []dc.Summary
	readFixture(t, "./mocks/data/containers.json", &all)
	for _, tc := range []struct {
		name     string
		statuses []string
		count    int
	}{
		{"running", []string{"running"}, 2},
		{"exited", []string{"exited"}, 1},
		{"restarting", []string{"restarting"}, 1},
		{"multiple", []string{"running", "exited"}, 3},
		{"duplicate", []string{"running", "running"}, 2},
		{"no matching status", []string{"created"}, 0},
		{"no requested statuses", nil, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := make(client.Filters)
			requested := map[string]bool{}
			for _, status := range tc.statuses {
				args.Add("status", status)
				requested[status] = true
			}
			if got := createFilterArgs(tc.statuses); !reflect.DeepEqual(got, args) {
				t.Fatal("status filter must use Docker SDK filter encoding and deduplicate statuses")
			}
			encoded, err := json.Marshal(args)
			if err != nil {
				t.Fatal(err)
			}
			query := url.Values{"filters": {string(encoded)}}
			var got []dc.Summary
			decodeResponse(t, serveContract(ListContainersHandler(tc.statuses...), "GET", "/v1.47/containers/json?"+query.Encode()), http.StatusOK, &got)
			expected := []dc.Summary{}
			for _, container := range all {
				if requested[string(container.State)] {
					expected = append(expected, container)
				}
			}
			if len(got) != tc.count || len(got) != len(expected) {
				t.Fatalf("filtered counts = %d, fixture-selected count = %d, want %d", len(got), len(expected), tc.count)
			}
			for i := range expected {
				if !reflect.DeepEqual(got[i], expected[i]) {
					t.Fatal("filter must preserve complete Docker summaries and fixture order")
				}
			}
		})
	}
}

func TestMutationHandlersDistinguishFoundAndMissing(t *testing.T) {
	useHTTPAssertions(t)
	for _, tc := range []struct {
		name, method, path string
		factory            func(string, FoundStatus) http.HandlerFunc
	}{
		{"kill", "POST", "/v1.47/containers/cid/kill", KillContainerHandler},
		{"remove", "DELETE", "/v1.47/containers/cid", RemoveContainerHandler},
	} {
		for _, found := range []FoundStatus{Found, Missing} {
			t.Run(tc.name+"/"+map[FoundStatus]string{Found: "found", Missing: "missing"}[found], func(t *testing.T) {
				response := serveContract(tc.factory("cid", found), tc.method, tc.path)
				if found {
					if response.Code != http.StatusNoContent || response.Body.Len() != 0 {
						t.Fatal("successful mutation must return 204 with no body")
					}
				} else if response.Code != http.StatusNotFound {
					t.Fatalf("missing container status = %d", response.Code)
				}
			})
		}
	}
}

func TestRemoveImageEmitsUntaggedImageThenDeletedParents(t *testing.T) {
	useHTTPAssertions(t)
	images := map[string][]string{"sha256:child": {"sha256:parent", "sha256:base"}, "sha256:leaf": nil}
	for _, id := range []string{"sha256:child", "sha256:leaf"} {
		var got []di.DeleteResponse
		response := serveContract(RemoveImageHandler(images), "DELETE", "/v1.47/images/"+id+"?force=1")
		decodeResponse(t, response, http.StatusOK, &got)
		expected := []di.DeleteResponse{{Untagged: id}, {Deleted: id}}
		for _, parent := range images[id] {
			expected = append(expected, di.DeleteResponse{Deleted: parent})
		}
		if !reflect.DeepEqual(got, expected) {
			t.Fatalf("deletion entries = %#v, want %#v", got, expected)
		}
	}
	response := serveContract(RemoveImageHandler(images), "DELETE", "/images/sha256:unknown")
	if response.Code != http.StatusNotFound {
		t.Fatalf("unknown image status = %d", response.Code)
	}
	if len(images) != 2 || len(images["sha256:child"]) != 2 {
		t.Fatal("response handler must not mutate the caller's deletion fixture")
	}
}

func TestHTTPHandlersRejectWrongMethodsIDsAndFilterQueries(t *testing.T) {
	useHTTPAssertions(t)
	t.Chdir("..")
	encoded, err := json.Marshal(createFilterArgs([]string{"running"}))
	if err != nil {
		t.Fatal(err)
	}
	listQuery := url.Values{"filters": {string(encoded)}}.Encode()
	cases := []struct {
		name, method, path, mismatch string
		factory                      func() http.HandlerFunc
	}{
		{"container method", "POST", "/containers/cid/json", "Method mismatch", func() http.HandlerFunc { return GetContainerHandler("cid", &dc.InspectResponse{ID: "cid"}) }},
		{"container ID", "GET", "/containers/other/json", "Path mismatch", func() http.HandlerFunc { return GetContainerHandler("cid", nil) }},
		{"image ID", "GET", "/images/other/json", "Path mismatch", func() http.HandlerFunc { return GetImageHandler(&di.InspectResponse{ID: "sha256:id"}) }},
		{"image method", "POST", "/images/sha256:id/json", "Method mismatch", func() http.HandlerFunc { return GetImageHandler(&di.InspectResponse{ID: "sha256:id"}) }},
		{"list query", "GET", "/containers/json", "RawQuery mismatch", func() http.HandlerFunc { return ListContainersHandler("running") }},
		{"list method", "POST", "/containers/json?" + listQuery, "Method mismatch", func() http.HandlerFunc { return ListContainersHandler("running") }},
		{"list path", "GET", "/containers/wrong?" + listQuery, "Path mismatch", func() http.HandlerFunc { return ListContainersHandler("running") }},
		{"kill method", "GET", "/containers/cid/kill", "Method mismatch", func() http.HandlerFunc { return KillContainerHandler("cid", Found) }},
		{"kill ID", "POST", "/containers/other/kill", "Path mismatch", func() http.HandlerFunc { return KillContainerHandler("cid", Missing) }},
		{"remove method", "POST", "/containers/cid", "Method mismatch", func() http.HandlerFunc { return RemoveContainerHandler("cid", Found) }},
		{"remove ID", "DELETE", "/containers/other", "Path mismatch", func() http.HandlerFunc { return RemoveContainerHandler("cid", Missing) }},
		{"remove image method", "GET", "/images/image", "Method mismatch", func() http.HandlerFunc { return RemoveImageHandler(map[string][]string{"image": nil}) }},
		{"remove image path", "DELETE", "/containers/image", "Path mismatch", func() http.HandlerFunc { return RemoveImageHandler(map[string][]string{"image": nil}) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler := tc.factory()
			// These handlers enforce requests through Gomega assertions rather than
			// HTTP error responses. Explicitly require rejection; never recover panics.
			failures := O.InterceptGomegaFailures(func() { serveContract(handler, tc.method, tc.path) })
			if len(failures) != 1 || !strings.Contains(failures[0], tc.mismatch) {
				t.Fatalf("request rejection = %v, want only %q", failures, tc.mismatch)
			}
		})
	}
}
