package mocks

import (
	"strings"
	"testing"
	"time"

	wt "github.com/PabloMz85/watchtower/pkg/types"
)

func TestMockClientSharesExplicitTestStateAndProtectsNamedContainer(t *testing.T) {
	keep := CreateMockContainer("keep", "/keep", "example/service:1", fixtureCreated)
	replace := CreateMockContainer("replace", "/replace", "example/service:1", fixtureCreated)
	data := &TestData{NameOfContainerToKeep: keep.Name(), Containers: []wt.Container{keep, replace}}
	client := CreateMockClient(data, true, false)
	if client.TestData != data || !client.pullImages || client.removeVolumes {
		t.Fatal("constructor did not retain state and options")
	}
	containers, err := client.ListContainers(func(wt.FilterableContainer) bool {
		t.Fatal("fixture client should return its supplied list, not evaluate the filter")
		return false
	})
	if err != nil || len(containers) != 2 || containers[0] != keep || containers[1] != replace {
		t.Fatal("list did not preserve fixture order and identities")
	}
	if err := client.StopContainer(keep, time.Second); err == nil || !strings.Contains(err.Error(), "instance we want to keep") {
		t.Fatal("protected container should reject stopping")
	}
	if err := client.StopContainer(replace, time.Second); err != nil {
		t.Fatal(err)
	}
	if data.TriedToRemoveImage() {
		t.Fatal("fresh client must not report image removal")
	}
	copyOfClient := client
	for _, c := range []MockClient{client, copyOfClient} {
		if err := c.RemoveImageByID("sha256:old"); err != nil {
			t.Fatal(err)
		}
	}
	if data.TriedToRemoveImageCount != 2 || !data.TriedToRemoveImage() {
		t.Fatal("value copies must update shared removal state once per call")
	}
	other := CreateMockClient(&TestData{}, false, true)
	if other.pullImages || !other.removeVolumes || other.TestData.TriedToRemoveImage() {
		t.Fatal("clients with different test data must remain isolated")
	}
	if got, err := client.GetContainer(keep.ID()); err != nil || got != keep {
		t.Fatal("get must return the first configured fixture")
	}
	if id, err := client.StartContainer(replace); err != nil || id != "" {
		t.Fatal("start stub must succeed without manufacturing an ID")
	}
	if err := client.RenameContainer(replace, "/renamed"); err != nil || replace.Name() != "/replace" {
		t.Fatal("rename stub should succeed without mutating supplied fixtures")
	}
	if !client.WarnOnHeadPullFailed(replace) {
		t.Fatal("fixture client should enable head-pull warnings")
	}
}

func TestMockClientStalenessUsesContainerNamesAndDefaultsToStale(t *testing.T) {
	data := &TestData{Staleness: map[string]bool{"/fresh": false, "/stale": true}}
	client := CreateMockClient(data, false, false)
	for _, tc := range []struct {
		name  string
		stale bool
	}{{"/fresh", false}, {"/stale", true}, {"/unspecified", true}} {
		t.Run(tc.name, func(t *testing.T) {
			c := CreateMockContainer("same-id", tc.name, "example/service:1", fixtureCreated)
			stale, image, err := client.IsContainerStale(c, wt.UpdateParams{})
			if err != nil || stale != tc.stale || image != "" {
				t.Fatalf("stale = %t, image = %q, err = %v", stale, image, err)
			}
		})
	}
	data.Staleness = nil
	c := CreateMockContainer("cid", "/fresh", "example/service:1", fixtureCreated)
	if stale, _, err := client.IsContainerStale(c, wt.UpdateParams{}); err != nil || !stale {
		t.Fatal("absent staleness map must default to stale")
	}
}

func TestMockClientLifecycleCommandExitContracts(t *testing.T) {
	client := CreateMockClient(&TestData{}, false, false)
	for _, tc := range []struct {
		command       string
		skip, failure bool
	}{
		{"/PreUpdateReturn0.sh", false, false},
		{"/PreUpdateReturn1.sh", false, true},
		{"/PreUpdateReturn75.sh", true, false},
		{"/unspecified-hook.sh", false, false},
	} {
		t.Run(tc.command, func(t *testing.T) {
			skip, err := client.ExecuteCommand("cid", tc.command, 1)
			if skip != tc.skip || (err != nil) != tc.failure {
				t.Fatalf("skip = %t, err = %v", skip, err)
			}
			if tc.failure && err.Error() != "command exited with code 1" {
				t.Fatalf("unexpected exit failure: %v", err)
			}
		})
	}
}
