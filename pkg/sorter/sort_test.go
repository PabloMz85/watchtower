package sorter_test

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/PabloMz85/watchtower/pkg/sorter"
	"github.com/PabloMz85/watchtower/pkg/types"
	dc "github.com/moby/moby/api/types/container"
)

// Only the metadata consumed by sorting is implemented. Unexpected calls to
// the rest of the Docker-facing interface fail instead of doing external work.
type sortableContainer struct {
	types.Container
	name  string
	info  dc.InspectResponse
	links []string
}

func (c *sortableContainer) Name() string                       { return c.name }
func (c *sortableContainer) ContainerInfo() *dc.InspectResponse { return &c.info }
func (c *sortableContainer) Links() []string                    { return c.links }

func newSortableContainer(name, created string, links ...string) *sortableContainer {
	return &sortableContainer{
		name: name, links: links,
		info: dc.InspectResponse{Created: created},
	}
}

func TestByCreatedSortsChronologicallyIncludingNanosecondsAndOffsets(t *testing.T) {
	oldest := newSortableContainer("/z-oldest", "2024-01-01T00:00:00Z")
	nano := newSortableContainer("/y-nanosecond", "2024-01-01T00:00:00.000000001Z")
	// This timestamp is later in UTC despite its earlier wall-clock date.
	offset := newSortableContainer("/x-offset", "2023-12-31T23:30:00-01:00")
	newest := newSortableContainer("/a-newest", "2024-01-02T00:00:00Z")
	containers := []types.Container{newest, offset, nano, oldest}
	sort.Sort(sorter.ByCreated(containers))
	want := []types.Container{oldest, nano, offset, newest}
	if !reflect.DeepEqual(containers, want) {
		t.Fatalf("created order = %v, want %v", containerNames(containers), containerNames(want))
	}
}

func TestByCreatedEqualInstantsHaveNoNameTieBreak(t *testing.T) {
	containers := sorter.ByCreated{
		newSortableContainer("/z", "2024-01-01T00:00:00Z"),
		newSortableContainer("/a", "2024-01-01T01:00:00+01:00"),
	}
	// The cleanup caller uses sort.Sort, not a stable sort or a name-based
	// secondary key. Equal creation instants are therefore equivalent.
	if containers.Less(0, 1) || containers.Less(1, 0) {
		t.Fatal("equal instants should compare equal regardless of name or timezone")
	}
	if containers.Less(0, 0) {
		t.Fatal("a creation timestamp must not precede itself")
	}
}

func TestSortByDependenciesOrdersBeforeDependents(t *testing.T) {
	for _, tc := range []struct {
		name  string
		names []string
		links map[string][]string
	}{
		{name: "nil input"},
		{name: "empty input", names: []string{}},
		{name: "singleton", names: []string{"/app"}},
		{name: "independent", names: []string{"/z", "/a", "/middle"}},
		{
			name: "reverse chain", names: []string{"/web", "/api", "/db"},
			links: map[string][]string{"/web": {"/api"}, "/api": {"/db"}},
		},
		{
			name: "already ordered chain", names: []string{"/db", "/api", "/web"},
			links: map[string][]string{"/web": {"/api"}, "/api": {"/db"}},
		},
		{
			name: "diamond with shared dependency", names: []string{"/web", "/api", "/worker", "/db"},
			links: map[string][]string{
				"/web": {"/api", "/worker"}, "/api": {"/db"}, "/worker": {"/db"},
			},
		},
		{
			name: "multiple branches and independent node", names: []string{"/worker", "/web", "/cache", "/db", "/independent"},
			links: map[string][]string{"/worker": {"/db"}, "/web": {"/db", "/cache"}},
		},
		{
			name: "unmatched links ignored", names: []string{"/web", "/db"},
			links: map[string][]string{"/web": {"/not-in-update", "/db"}, "/db": {"/external"}},
		},
		{
			name: "repeated links do not duplicate containers", names: []string{"/web", "/db"},
			links: map[string][]string{"/web": {"/db", "/db"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var input []types.Container
			if tc.names != nil {
				input = make([]types.Container, 0, len(tc.names))
			}
			originals := map[string]*sortableContainer{}
			linksBefore := map[string][]string{}
			for _, name := range tc.names {
				c := newSortableContainer(name, "2024-01-01T00:00:00Z", tc.links[name]...)
				input = append(input, c)
				originals[name] = c
				linksBefore[name] = append([]string(nil), c.links...)
			}

			// Sorting may reuse the input slice's backing array. Preserve the
			// container identities separately; do not assume slice immutability.
			got, err := sorter.SortByDependencies(input)
			if err != nil {
				t.Fatalf("SortByDependencies: %v", err)
			}
			if len(got) != len(originals) {
				t.Fatalf("got %d containers, want %d: %v", len(got), len(originals), containerNames(got))
			}
			positions := map[string]int{}
			for i, c := range got {
				if _, duplicate := positions[c.Name()]; duplicate {
					t.Fatalf("container %q appears more than once", c.Name())
				}
				if c != originals[c.Name()] {
					t.Errorf("sort replaced the original container %q", c.Name())
				}
				positions[c.Name()] = i
			}
			for name, c := range originals {
				position, present := positions[name]
				if !present {
					t.Errorf("missing container %q", name)
					continue
				}
				if c.name != name || c.info.Created != "2024-01-01T00:00:00Z" || !reflect.DeepEqual(c.links, linksBefore[name]) {
					t.Errorf("sort mutated metadata for %q", name)
				}
				for _, dependency := range linksBefore[name] {
					if dependencyPosition, matched := positions[dependency]; matched && dependencyPosition >= position {
						t.Errorf("dependency %q must precede %q: %v", dependency, name, containerNames(got))
					}
				}
			}
		})
	}
}

func TestSortByDependenciesRejectsCyclesWithoutPartialResults(t *testing.T) {
	for _, tc := range []struct {
		name  string
		names []string
		links map[string][]string
	}{
		{"self link", []string{"/app"}, map[string][]string{"/app": {"/app"}}},
		{"two node cycle", []string{"/app", "/db"}, map[string][]string{"/app": {"/db"}, "/db": {"/app"}}},
		{
			"cycle after independent node", []string{"/independent", "/app", "/db", "/cache"},
			map[string][]string{"/app": {"/db"}, "/db": {"/cache"}, "/cache": {"/app"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var input []types.Container
			for _, name := range tc.names {
				input = append(input, newSortableContainer(name, "2024-01-01T00:00:00Z", tc.links[name]...))
			}
			got, err := sorter.SortByDependencies(input)
			if err == nil || !strings.Contains(err.Error(), "circular reference") {
				t.Fatalf("cycle should return a circular-reference error, got result=%v err=%v", containerNames(got), err)
			}
			if got != nil {
				t.Fatalf("cycle returned a usable partial result: %v", containerNames(got))
			}
		})
	}
}

func containerNames(containers []types.Container) []string {
	names := make([]string, len(containers))
	for i, c := range containers {
		names[i] = c.Name()
	}
	return names
}
