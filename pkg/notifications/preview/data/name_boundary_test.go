package data

import "testing"

func TestGeneratedContainerNamesRemainUniqueForLargeReports(t *testing.T) {
	preview := New()
	count := 3*len(containerNames) + 1
	seen := make(map[string]bool, count)
	for index := 0; index < count; index++ {
		preview.AddFromState(UpdatedState)
		containers := preview.Report().Updated()
		if len(containers) != index+1 {
			t.Fatalf("report lost a container at index %d", index)
		}
		name := containers[index].Name()
		if name == "" || seen[name] {
			t.Fatalf("container %d has empty or repeated name %q", index, name)
		}
		seen[name] = true
	}
}
