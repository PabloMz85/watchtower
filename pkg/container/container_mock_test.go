package container

import (
	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
	dockerContainer "github.com/moby/moby/api/types/container"
	dockerimage "github.com/moby/moby/api/types/image"
	"github.com/moby/moby/api/types/network"
)

type MockContainerUpdate func(*dockerContainer.InspectResponse, *dockerimage.InspectResponse)

func MockContainer(updates ...MockContainerUpdate) *Container {
	containerInfo := dockerContainer.InspectResponse{

		ID:         "container_id",
		Image:      "image",
		Name:       "test-containrrr",
		HostConfig: &dockerContainer.HostConfig{},

		Config: &dockerContainer.Config{
			Labels: map[string]string{},
		},
	}
	image := dockerimage.InspectResponse{
		ID:     "image_id",
		Config: &dockerspec.DockerOCIImageConfig{},
	}

	for _, update := range updates {
		update(&containerInfo, &image)
	}
	return NewContainer(&containerInfo, &image)
}

func WithPortBindings(portBindingSources ...string) MockContainerUpdate {
	return func(c *dockerContainer.InspectResponse, i *dockerimage.InspectResponse) {
		portBindings := network.PortMap{}
		for _, pbs := range portBindingSources {
			portBindings[network.MustParsePort(pbs)] = []network.PortBinding{}
		}
		c.HostConfig.PortBindings = portBindings
	}
}

func WithImageName(name string) MockContainerUpdate {
	return func(c *dockerContainer.InspectResponse, i *dockerimage.InspectResponse) {
		c.Config.Image = name
		i.RepoTags = append(i.RepoTags, name)
	}
}

func WithLinks(links []string) MockContainerUpdate {
	return func(c *dockerContainer.InspectResponse, i *dockerimage.InspectResponse) {
		c.HostConfig.Links = links
	}
}

func WithLabels(labels map[string]string) MockContainerUpdate {
	return func(c *dockerContainer.InspectResponse, i *dockerimage.InspectResponse) {
		c.Config.Labels = labels
	}
}

func WithContainerState(state dockerContainer.State) MockContainerUpdate {
	return func(cnt *dockerContainer.InspectResponse, img *dockerimage.InspectResponse) {
		cnt.State = &state
	}
}

func WithHealthcheck(healthConfig dockerContainer.HealthConfig) MockContainerUpdate {
	return func(cnt *dockerContainer.InspectResponse, img *dockerimage.InspectResponse) {
		cnt.Config.Healthcheck = &healthConfig
	}
}

func WithImageHealthcheck(healthConfig dockerContainer.HealthConfig) MockContainerUpdate {
	return func(cnt *dockerContainer.InspectResponse, img *dockerimage.InspectResponse) {
		img.Config.Healthcheck = &healthConfig
	}
}
