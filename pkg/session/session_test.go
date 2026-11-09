package session_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/PabloMz85/watchtower/pkg/session"
	"github.com/PabloMz85/watchtower/pkg/types"
)

// Unused methods deliberately remain unimplemented: these entrypoints only read
// the identity and image metadata of a container, never contact a Docker daemon.
type sessionContainer struct {
	types.Container
	id        types.ContainerID
	name      string
	image     types.ImageID
	imageName string
}

func (c *sessionContainer) ID() types.ContainerID      { return c.id }
func (c *sessionContainer) Name() string               { return c.name }
func (c *sessionContainer) SafeImageID() types.ImageID { return c.image }
func (c *sessionContainer) ImageName() string          { return c.imageName }

func newSessionContainer(id, name string) *sessionContainer {
	return &sessionContainer{
		id: types.ContainerID(id), name: name,
		image: "sha256:old", imageName: "registry.example/app:stable",
	}
}

func TestUpdateFromContainerCopiesMetadataAndState(t *testing.T) {
	c := newSessionContainer("container-id", "/app")
	for _, tc := range []struct {
		name  string
		state session.State
		want  string
	}{
		{"unknown", session.UnknownState, "Unknown"},
		{"skipped", session.SkippedState, "Skipped"},
		{"scanned", session.ScannedState, "Scanned"},
		{"updated", session.UpdatedState, "Updated"},
		{"failed", session.FailedState, "Failed"},
		{"fresh", session.FreshState, "Fresh"},
		{"stale", session.StaleState, "Stale"},
		{"unrecognized", session.State(100), "Unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status := session.UpdateFromContainer(c, "sha256:new", tc.state)
			if status.ID() != c.id || status.Name() != c.name || status.ImageName() != c.imageName {
				t.Fatalf("identity = (%q, %q, %q), want (%q, %q, %q)", status.ID(), status.Name(), status.ImageName(), c.id, c.name, c.imageName)
			}
			if status.CurrentImageID() != c.image || status.LatestImageID() != "sha256:new" {
				t.Errorf("images = (%q, %q), want (%q, sha256:new)", status.CurrentImageID(), status.LatestImageID(), c.image)
			}
			assertStatus(t, status, tc.want, "")
		})
	}
}

func TestProgressTransitionsAndReplacement(t *testing.T) {
	progress := session.Progress{}
	app := newSessionContainer("app-id", "/app")
	db := newSessionContainer("db-id", "/db")
	progress.AddScanned(app, "sha256:new-app")
	progress.AddScanned(db, "sha256:new-db")
	assertStatus(t, progress[app.ID()], "Scanned", "")
	assertStatus(t, progress[db.ID()], "Scanned", "")

	progress.MarkForUpdate(app.ID())
	assertStatus(t, progress[app.ID()], "Updated", "")
	assertStatus(t, progress[db.ID()], "Scanned", "")

	progress.UpdateFailed(map[types.ContainerID]error{
		app.ID(): errors.New("restart failed"),
		db.ID():  errors.New("stop failed"),
	})
	assertStatus(t, progress[app.ID()], "Failed", "restart failed")
	assertStatus(t, progress[db.ID()], "Failed", "stop failed")
	if progress[app.ID()].LatestImageID() != "sha256:new-app" {
		t.Fatal("failure lost the scanned image metadata")
	}
	progress.UpdateFailed(nil)
	assertStatus(t, progress[app.ID()], "Failed", "restart failed")

	replacement := newSessionContainer("app-id", "/replacement")
	replacement.image = "sha256:replacement-old"
	status := session.UpdateFromContainer(replacement, "sha256:replacement-new", session.ScannedState)
	progress.Add(status)
	if len(progress) != 2 || progress[app.ID()] != status {
		t.Fatalf("Add should replace the same container ID: %#v", progress)
	}
	assertStatus(t, progress[app.ID()], "Scanned", "")
	if status.Name() != replacement.Name() || status.CurrentImageID() != replacement.image {
		t.Fatal("replacement did not retain its own container metadata")
	}
	assertStatus(t, progress[db.ID()], "Failed", "stop failed")
}

func TestProgressAddSkippedRetainsCurrentImageAndError(t *testing.T) {
	for _, err := range []error{nil, errors.New("registry unavailable")} {
		progress := session.Progress{}
		c := newSessionContainer("skipped-id", "/skipped")
		progress.AddSkipped(c, err)
		wantError := ""
		if err != nil {
			wantError = err.Error()
		}
		status := progress[c.ID()]
		assertStatus(t, status, "Skipped", wantError)
		if status.CurrentImageID() != c.image || status.LatestImageID() != c.image {
			t.Fatal("skipped container must retain its original image")
		}
	}
}

func TestReportPartitionsSessionAndAllDeduplicatesContainers(t *testing.T) {
	progress := session.Progress{}
	wantGroups := map[string]map[types.ContainerID]bool{}
	for _, category := range []string{"Updated", "Failed", "Skipped", "Stale", "Fresh"} {
		wantGroups[category] = map[types.ContainerID]bool{}
		// Opposing names and IDs keep identity independent from display names.
		for _, suffix := range []string{"z", "a"} {
			id := category + "-" + suffix
			nameSuffix := "z"
			if suffix == "z" {
				nameSuffix = "a"
			}
			c := newSessionContainer(id, "/"+category+"-"+nameSuffix)
			wantGroups[category][c.ID()] = true
			if category == "Skipped" {
				progress.AddSkipped(c, errors.New("cannot inspect image"))
				continue
			}
			newImage := types.ImageID("sha256:new")
			if category == "Fresh" {
				newImage = c.image
			}
			progress.AddScanned(c, newImage)
			if category == "Updated" || category == "Failed" || category == "Fresh" {
				// The update caller marks even unchanged containers for update;
				// reporting must classify unchanged images as Fresh instead.
				progress.MarkForUpdate(c.ID())
			}
			if category == "Failed" {
				progress.UpdateFailed(map[types.ContainerID]error{c.ID(): errors.New("restart failed")})
			}
		}
	}

	report := progress.Report()
	groups := map[string][]types.ContainerReport{
		"Updated": report.Updated(), "Failed": report.Failed(), "Skipped": report.Skipped(),
		"Stale": report.Stale(), "Fresh": report.Fresh(),
	}
	partitioned := 0
	for category, reports := range groups {
		if len(reports) != 2 {
			t.Fatalf("%s count = %d, want 2", category, len(reports))
		}
		seen := map[types.ContainerID]bool{}
		for _, status := range reports {
			if !wantGroups[category][status.ID()] || seen[status.ID()] {
				t.Errorf("unexpected or duplicate %s ID: %q", category, status.ID())
			}
			seen[status.ID()] = true
			wantError := ""
			if category == "Failed" {
				wantError = "restart failed"
			} else if category == "Skipped" {
				wantError = "cannot inspect image"
			}
			assertStatus(t, status, category, wantError)
			if status != progress[status.ID()] {
				t.Errorf("report lost the status for %q", status.ID())
			}
		}
		if category != "Skipped" {
			partitioned += len(reports)
		}
	}
	if len(report.Scanned()) != partitioned {
		t.Fatalf("scanned count = %d, want %d", len(report.Scanned()), partitioned)
	}
	scanned := map[types.ContainerID]bool{}
	for _, status := range report.Scanned() {
		if status.State() == "Skipped" || scanned[status.ID()] {
			t.Errorf("unexpected scanned entry %q (%s)", status.ID(), status.State())
		}
		scanned[status.ID()] = true
	}
	for id, status := range progress {
		if scanned[id] != (status.State() != "Skipped") {
			t.Errorf("scanned membership is wrong for %q", id)
		}
	}

	all := report.All()
	if len(all) != len(progress) {
		t.Fatalf("All count = %d, want %d unique containers", len(all), len(progress))
	}
	seen := map[types.ContainerID]bool{}
	for _, status := range all {
		if progress[status.ID()] != status || seen[status.ID()] {
			t.Errorf("unexpected or duplicated All entry %q", status.ID())
		}
		seen[status.ID()] = true
	}
	if !reflect.DeepEqual(reportIDs(all), reportIDs(report.All())) {
		t.Error("repeated All calls changed the order or membership")
	}
	// All builds a combined slice; replacing an element must not corrupt a category.
	all[0] = nil
	for _, status := range report.All() {
		if status == nil {
			t.Fatal("mutating the All slice corrupted the report")
		}
	}
}

func TestEmptyReport(t *testing.T) {
	for _, progress := range []session.Progress{nil, {}} {
		for _, report := range []types.Report{session.NewReport(progress), progress.Report()} {
			for name, entries := range map[string][]types.ContainerReport{
				"scanned": report.Scanned(), "updated": report.Updated(), "failed": report.Failed(),
				"skipped": report.Skipped(), "stale": report.Stale(), "fresh": report.Fresh(), "all": report.All(),
			} {
				if len(entries) != 0 {
					t.Errorf("empty report %s = %v", name, entries)
				}
			}
		}
	}
}

func assertStatus(t *testing.T, status types.ContainerReport, state, message string) {
	t.Helper()
	if status.State() != state || status.Error() != message {
		t.Errorf("status = (%q, %q), want (%q, %q)", status.State(), status.Error(), state, message)
	}
}

func reportIDs(reports []types.ContainerReport) []types.ContainerID {
	ids := make([]types.ContainerID, len(reports))
	for i, report := range reports {
		ids[i] = report.ID()
	}
	return ids
}
