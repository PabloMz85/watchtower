package mocks

import (
	"reflect"
	"sort"
	"testing"

	"github.com/PabloMz85/watchtower/pkg/session"
	wt "github.com/PabloMz85/watchtower/pkg/types"
)

func TestProgressReportBuildsIndependentStateGroups(t *testing.T) {
	report := CreateMockProgressReport(
		session.FailedState, session.UpdatedState, session.FreshState, session.SkippedState,
		session.UpdatedState, session.SkippedState, session.FailedState, session.FreshState,
	)
	groups := []struct {
		name    string
		reports []wt.ContainerReport
		names   []string
	}{
		{"Updated", report.Updated(), []string{"updt1", "updt2"}},
		{"Failed", report.Failed(), []string{"fail1", "fail2"}},
		{"Fresh", report.Fresh(), []string{"frsh1", "frsh2"}},
		{"Skipped", report.Skipped(), []string{"skip1", "skip2"}},
	}
	seen := map[wt.ContainerID]bool{}
	for _, group := range groups {
		t.Run(group.name, func(t *testing.T) {
			if len(group.reports) != len(group.names) {
				t.Fatalf("got %d reports, want %d", len(group.reports), len(group.names))
			}
			for i, c := range group.reports {
				if c.Name() != group.names[i] || c.State() != group.name || c.ImageName() != "mock/"+c.Name()+":latest" {
					t.Fatal("report lost state-specific identity or configured image name")
				}
				if seen[c.ID()] {
					t.Fatalf("duplicate container ID %s", c.ID())
				}
				seen[c.ID()] = true
				if i > 0 && group.reports[i-1].ID() >= c.ID() {
					t.Fatal("state group is not sorted by ID")
				}
				switch group.name {
				case "Failed":
					if c.Error() != "accidentally the whole container" || c.CurrentImageID() == c.LatestImageID() {
						t.Fatal("failed update must retain its error and changed image")
					}
				case "Skipped":
					if c.Error() != "unpossible" || c.CurrentImageID() != c.LatestImageID() {
						t.Fatal("skipped scan must retain its error and current image")
					}
				case "Fresh":
					if c.Error() != "" || c.CurrentImageID() != c.LatestImageID() {
						t.Fatal("fresh report must have no error or image change")
					}
				case "Updated":
					if c.Error() != "" || c.CurrentImageID() == c.LatestImageID() {
						t.Fatal("updated report must have a changed image and no error")
					}
				}
			}
		})
	}
	if len(report.Scanned()) != 6 || len(report.Stale()) != 0 || len(report.All()) != 8 || len(seen) != 8 {
		t.Fatal("report category totals do not match supplied supported states")
	}
	allIDs := make([]string, 0, len(report.All()))
	for _, c := range report.All() {
		allIDs = append(allIDs, string(c.ID()))
	}
	if !sort.StringsAreSorted(allIDs) {
		t.Fatal("combined report must be deterministically ordered")
	}
	scannedNames := make([]string, 0, len(report.Scanned()))
	for _, c := range report.Scanned() {
		scannedNames = append(scannedNames, c.Name())
	}
	sort.Strings(scannedNames)
	if !reflect.DeepEqual(scannedNames, []string{"fail1", "fail2", "frsh1", "frsh2", "updt1", "updt2"}) {
		t.Fatal("skipped containers must not be counted as scanned")
	}
	another := CreateMockProgressReport(session.UpdatedState)
	if len(another.All()) != 1 || another.Updated()[0].Name() != "updt1" || len(report.All()) != 8 {
		t.Fatal("report factories must reset indexes and keep reports independent")
	}
}

func TestEmptyProgressReportHasNoContainers(t *testing.T) {
	report := CreateMockProgressReport()
	for _, group := range [][]wt.ContainerReport{report.All(), report.Scanned(), report.Updated(), report.Failed(), report.Fresh(), report.Skipped(), report.Stale()} {
		if len(group) != 0 {
			t.Fatal("empty factory input created report entries")
		}
	}
}
