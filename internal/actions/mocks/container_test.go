package mocks

import (
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
	"time"

	wt "github.com/PabloMz85/watchtower/pkg/types"
	dc "github.com/moby/moby/api/types/container"
	di "github.com/moby/moby/api/types/image"
)

var fixtureCreated = time.Date(2024, time.February, 3, 4, 5, 6, 0, time.UTC)

func TestCreateMockContainerInitializesIndependentDockerMetadata(t *testing.T) {
	c := CreateMockContainer("container-id", "/service", "example/service:1", fixtureCreated)
	info := c.ContainerInfo()
	if c.ID() != "container-id" || c.Name() != "/service" || c.ImageName() != "example/service:1" || c.ImageID() != "example/service:1" {
		t.Fatalf("constructor lost container or image identity")
	}
	if info.Created != fixtureCreated.String() || info.Image != "example/service:1" || info.Config.Image != "example/service:1" {
		t.Fatal("Docker inspect metadata does not preserve constructor arguments")
	}
	if info.HostConfig == nil || info.HostConfig.PortBindings == nil || info.Config.Labels == nil || info.Config.ExposedPorts == nil {
		t.Fatal("default metadata must be initialized for callers to add labels and ports")
	}
	if !reflect.DeepEqual(c.ImageInfo().RepoDigests, []string{"example/service:1"}) || !c.HasImageInfo() {
		t.Fatal("default image metadata must include its ID as a digest")
	}
	other := CreateMockContainer("other-id", "/other", "example/service:1", fixtureCreated)
	info.Config.Labels["only-first"] = "true"
	c.ImageInfo().RepoDigests[0] = "changed"
	if len(other.ContainerInfo().Config.Labels) != 0 || other.ImageInfo().RepoDigests[0] != "example/service:1" {
		t.Fatal("constructors share mutable metadata between containers")
	}
}

func TestCreateMockImageInfoAndDigestOverride(t *testing.T) {
	info := CreateMockImageInfo("sha256:old")
	if info.ID != "sha256:old" || !reflect.DeepEqual(info.RepoDigests, []string{"sha256:old"}) {
		t.Fatal("image info lost ID or default digest")
	}
	c := CreateMockContainerWithDigest("container-id", "/service", "sha256:old", fixtureCreated, "example/service@sha256:new")
	if c.ImageID() != "sha256:old" || !reflect.DeepEqual(c.ImageInfo().RepoDigests, []string{"example/service@sha256:new"}) {
		t.Fatal("digest override must not overwrite the image ID")
	}
	if info.RepoDigests[0] != "sha256:old" {
		t.Fatal("digest override changed another image")
	}
}

func TestImageInfoConstructorsPreserveSuppliedMetadata(t *testing.T) {
	image := di.InspectResponse{ID: "sha256:inspected", RepoDigests: []string{"example/service@sha256:digest"}, Architecture: "arm64"}
	for _, tc := range []struct {
		name          string
		makeContainer func() wt.Container
	}{
		{"value", func() wt.Container {
			return CreateMockContainerWithImageInfo("cid", "/service", "example/service:2", fixtureCreated, image)
		}},
		{"pointer", func() wt.Container {
			return CreateMockContainerWithImageInfoP("cid", "/service", "example/service:2", fixtureCreated, &image)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.makeContainer()
			if !reflect.DeepEqual(c.ImageInfo(), &image) || c.ImageID() != "sha256:inspected" || c.ImageName() != "example/service:2" {
				t.Fatal("supplied inspection and configured image name must remain distinct")
			}
			if c.ID() != "cid" || c.Name() != "/service" || c.ContainerInfo().Created != fixtureCreated.String() {
				t.Fatal("container metadata was lost")
			}
		})
	}
	c := CreateMockContainerWithImageInfoP("cid", "/service", "example/service:2", fixtureCreated, &image)
	image.ID = "sha256:changed"
	if c.ImageInfo() != &image || c.ImageID() != "sha256:changed" {
		t.Fatal("pointer constructor must retain the supplied image inspection")
	}
	withoutImage := CreateMockContainerWithImageInfoP("cid", "/service", "example/service:2", fixtureCreated, nil)
	if withoutImage.HasImageInfo() || withoutImage.SafeImageID() != "" {
		t.Fatal("nil image info must remain absent")
	}
}

func TestConfigConstructorFeedsRealContainerAccessors(t *testing.T) {
	for _, running := range []bool{false, true} {
		for _, restarting := range []bool{false, true} {
			config := &dc.Config{Image: "example/configured:3", Labels: map[string]string{
				"com.centurylinklabs.watchtower.enable": "true",
				"com.centurylinklabs.watchtower.scope":  "test-scope",
			}, Cmd: []string{"serve"}}
			c := CreateMockContainerWithConfig("cid", "/configured", "sha256:old", running, restarting, fixtureCreated, config)
			if c.ContainerInfo().Config != config || c.ImageName() != config.Image || c.ImageID() != "sha256:old" {
				t.Fatal("config constructor must preserve caller config separately from image identity")
			}
			if c.IsRunning() != running || c.IsRestarting() != restarting {
				t.Fatal("Docker state flags were not preserved independently")
			}
			if enabled, set := c.Enabled(); !enabled || !set {
				t.Fatal("enable label did not reach the real container accessor")
			}
			if scope, set := c.Scope(); scope != "test-scope" || !set {
				t.Fatal("scope label did not reach the real container accessor")
			}
			if c.ContainerInfo().Created != fixtureCreated.String() || c.ContainerInfo().HostConfig.PortBindings == nil {
				t.Fatal("config constructor lost creation metadata or writable port bindings")
			}
		}
	}
}

func TestLinksConstructorFeedsRealDependencyResolution(t *testing.T) {
	links := []string{"/database:/service/database", "/cache:/service/cache"}
	image := CreateMockImageInfo("sha256:old")
	c := CreateMockContainerWithLinks("cid", "/service", "example/service:1", fixtureCreated, links, image)
	if !reflect.DeepEqual(c.ContainerInfo().HostConfig.Links, links) || !reflect.DeepEqual(c.Links(), []string{"/database", "/cache"}) {
		t.Fatal("links must retain Docker aliases while exposing dependency container names")
	}
	if c.ImageInfo() != image || c.ID() != "cid" || c.Name() != "/service" || c.ContainerInfo().Created != fixtureCreated.String() {
		t.Fatal("links constructor lost supplied metadata")
	}
}

func TestProgressContainerHasStableUniqueIdentities(t *testing.T) {
	first, latest := CreateContainerForProgress(0, 11, "updated-%d")
	again, sameLatest := CreateContainerForProgress(0, 11, "updated-%d")
	second, secondLatest := CreateContainerForProgress(1, 11, "updated-%d")
	if first.ID() != again.ID() || latest != sameLatest || first.ID() == second.ID() || latest == secondLatest {
		t.Fatal("progress identities must be deterministic and unique per index")
	}
	for _, id := range []string{string(first.ID()), string(first.ImageID()), string(latest)} {
		if len(id) != 64 {
			t.Fatalf("progress ID length = %d, want 64", len(id))
		}
		if _, err := hex.DecodeString(id); err != nil {
			t.Fatalf("progress ID is not hexadecimal: %v", err)
		}
	}
	if !strings.HasPrefix(string(first.ID()), "c7911") || !strings.HasPrefix(string(first.ImageID()), "01d11") || !strings.HasPrefix(string(latest), "d0a11") {
		t.Fatal("container, current image, and latest image need distinct stable prefixes")
	}
	if first.Name() != "updated-1" || second.Name() != "updated-2" || first.ImageName() != "mock/updated-1:latest" {
		t.Fatal("progress names must use one-based indexing and configured image names")
	}
	if first.ImageID() == latest || !first.IsRunning() || first.IsRestarting() {
		t.Fatal("progress container must represent a running container with a newer image")
	}
}
