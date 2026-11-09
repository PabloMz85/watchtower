package data

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/PabloMz85/watchtower/pkg/types"
)

func TestReportAllSortsByIDWithoutReorderingCategories(t *testing.T) {
	p := New()
	states := []State{ScannedState, UpdatedState, FailedState, SkippedState, StaleState, FreshState}
	for i, state := range states {
		for _, id := range []string{fmt.Sprintf("z%d", i), fmt.Sprintf("a%d", i)} {
			p.addContainer(containerStatus{containerID: types.ContainerID(id), containerName: "/same-name", state: state})
		}
	}
	var ids []string
	for _, c := range p.Report().All() {
		ids = append(ids, string(c.ID()))
	}
	want := []string{"a0", "a1", "a2", "a3", "a4", "a5", "z0", "z1", "z2", "z3", "z4", "z5"}
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("All() IDs = %v, want %v", ids, want)
	}
	for i, state := range states {
		category := reportCategories(p.Report())[state]
		if len(category) != 2 || category[0].ID() != types.ContainerID(fmt.Sprintf("z%d", i)) || category[1].ID() != types.ContainerID(fmt.Sprintf("a%d", i)) {
			t.Errorf("All() changed insertion order in %s category: %v", state, category)
		}
	}
}

func TestReportAllDeduplicatesByIDWithOutcomePrecedence(t *testing.T) {
	// A more specific outcome takes precedence over the same container's scan.
	precedence := []State{UpdatedState, FailedState, SkippedState, StaleState, FreshState, ScannedState}
	for i, preferred := range precedence {
		t.Run(string(preferred), func(t *testing.T) {
			p := New()
			// Insert in reverse precedence to ensure insertion order across
			// categories does not choose which report survives.
			for j := len(precedence) - 1; j >= i; j-- {
				p.addContainer(containerStatus{containerID: "shared-id", containerName: "/" + string(precedence[j]), state: precedence[j]})
			}
			p.addContainer(containerStatus{containerID: "shared-id", containerName: "/later-duplicate", state: preferred})
			all := p.Report().All()
			if len(all) != 1 {
				t.Fatalf("All() returned %d reports for shared-id, want 1", len(all))
			}
			if all[0].State() != string(preferred) || all[0].Name() != "/"+string(preferred) {
				t.Fatalf("All() retained state=%q name=%q, want state=%q name=%q", all[0].State(), all[0].Name(), preferred, "/"+string(preferred))
			}
			if got := len(reportCategories(p.Report())[preferred]); got != 2 {
				t.Errorf("All() removed a category entry: got %d, want 2", got)
			}
		})
	}
}

func TestEmptyReportAll(t *testing.T) {
	r := &report{}
	if got := r.All(); len(got) != 0 {
		t.Fatalf("empty report All() = %v", got)
	}
	for state, category := range reportCategories(r) {
		if len(category) != 0 {
			t.Errorf("empty report %s category = %v", state, category)
		}
	}
}
