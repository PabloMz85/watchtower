package container

import (
	"testing"
	"time"

	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
	dockercontainer "github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/image"
)

func TestGetCreateConfigHealthcheckStartInterval(t *testing.T) {
	for _, tc := range []struct {
		name      string
		container time.Duration
		image     time.Duration
		want      time.Duration
	}{
		{name: "image default is cleared", container: 5 * time.Second, image: 5 * time.Second},
		{name: "user override is retained", container: 2 * time.Second, image: 5 * time.Second, want: 2 * time.Second},
		{name: "zero default remains zero"},
		{name: "zero container value remains zero", image: 5 * time.Second},
		{name: "override of zero default is retained", container: 2 * time.Second, want: 2 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewContainer(&dockercontainer.InspectResponse{
				Config:     &dockercontainer.Config{Image: "application:latest", Healthcheck: &dockercontainer.HealthConfig{StartInterval: tc.container}},
				HostConfig: &dockercontainer.HostConfig{},
			}, &image.InspectResponse{Config: &dockerspec.DockerOCIImageConfig{
				DockerOCIImageConfigExt: dockerspec.DockerOCIImageConfigExt{
					Healthcheck: &dockerspec.HealthcheckConfig{StartInterval: tc.image},
				},
			}})
			if got := c.GetCreateConfig().Healthcheck.StartInterval; got != tc.want {
				t.Errorf("StartInterval = %s, want %s", got, tc.want)
			}
		})
	}
}
