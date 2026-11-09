package mocks

import (
	"testing"

	"github.com/PabloMz85/watchtower/pkg/container"
	"github.com/PabloMz85/watchtower/pkg/filters"
	dc "github.com/moby/moby/api/types/container"
)

// The generated wrapper is exercised only as input to real production filters.
// Docker DTOs and the real Container supply the same accessor values it replaces.
func TestFilterableWrapperSupportsRealFilterConsumers(t *testing.T) {
	for _, dynamic := range []bool{false, true} {
		mode := "static"
		if dynamic {
			mode = "dynamic"
		}
		t.Run(mode, func(t *testing.T) {
			for _, tc := range []struct {
				name, containerName, image, enabled, scope string
				accepted, watchtower                       bool
			}{
				{"matching", "/service", "example/service:1", "true", "production", true, true},
				{"disabled", "/service", "example/service:1", "false", "production", false, false},
				{"no enable label", "/service", "example/service:1", "", "production", false, false},
				{"other scope", "/service", "example/service:1", "true", "staging", false, false},
				{"no scope", "/service", "example/service:1", "true", "", false, false},
				{"other name", "/other", "example/service:1", "true", "production", false, false},
				{"other image", "/service", "example/other:1", "true", "production", false, false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					labels := map[string]string{}
					if tc.enabled != "" {
						labels["com.centurylinklabs.watchtower.enable"] = tc.enabled
					}
					if tc.scope != "" {
						labels["com.centurylinklabs.watchtower.scope"] = tc.scope
					}
					if tc.watchtower {
						labels["com.centurylinklabs.watchtower"] = "true"
					}
					real := container.NewContainer(&dc.InspectResponse{Name: tc.containerName, Config: &dc.Config{Image: tc.image, Labels: labels}}, nil)
					wrapper := &FilterableContainer{}
					if dynamic {
						wrapper.On("Enabled").Return(func() bool { value, _ := real.Enabled(); return value }, func() bool { _, set := real.Enabled(); return set })
						wrapper.On("Scope").Return(func() string { value, _ := real.Scope(); return value }, func() bool { _, set := real.Scope(); return set })
						wrapper.On("Name").Return(real.Name)
						wrapper.On("ImageName").Return(real.ImageName)
						wrapper.On("IsWatchtower").Return(real.IsWatchtower)
					} else {
						enabled, hasEnabled := real.Enabled()
						scope, hasScope := real.Scope()
						wrapper.On("Enabled").Return(enabled, hasEnabled)
						wrapper.On("Scope").Return(scope, hasScope)
						wrapper.On("Name").Return(real.Name())
						wrapper.On("ImageName").Return(real.ImageName())
						wrapper.On("IsWatchtower").Return(real.IsWatchtower())
					}
					base, _ := filters.BuildFilter([]string{"service"}, nil, true, "production")
					filter := filters.FilterByImage([]string{"example/service"}, base)
					if got := filter(real); got != tc.accepted {
						t.Fatalf("real DTO producer filter = %t, want %t", got, tc.accepted)
					}
					if got := filter(wrapper); got != tc.accepted {
						t.Fatalf("wrapper filter = %t, want %t", got, tc.accepted)
					}
					if got := filters.WatchtowerContainersFilter(wrapper); got != tc.watchtower {
						t.Fatalf("watchtower selection = %t, want %t", got, tc.watchtower)
					}
					if dynamic && tc.accepted {
						labels["com.centurylinklabs.watchtower.enable"] = "false"
						if filter(wrapper) {
							t.Fatal("function-backed wrapper must reflect updated producer labels during filtering")
						}
					}
				})
			}
		})
	}
}
