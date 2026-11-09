package sorter_test

import (
	"testing"
	"time"

	"github.com/PabloMz85/watchtower/pkg/sorter"
)

func TestByCreatedInvalidTimestampFallback(t *testing.T) {
	past := time.Now().Add(-time.Hour).Format(time.RFC3339Nano)
	future := time.Now().Add(time.Hour).Format(time.RFC3339Nano)
	for _, tc := range []struct {
		name, first, second string
		want                bool
	}{
		{name: "old date precedes invalid second date", first: past, second: "invalid", want: true},
		{name: "invalid first date follows old date", first: "invalid", second: past},
		{name: "invalid first date precedes future date", first: "invalid", second: future, want: true},
		{name: "future date follows invalid second date", first: future, second: "invalid"},
		{name: "two invalid dates compare as equivalent", first: "invalid-one", second: "invalid-two"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			containers := sorter.ByCreated{
				newSortableContainer("/first", tc.first),
				newSortableContainer("/second", tc.second),
			}
			if got := containers.Less(0, 1); got != tc.want {
				t.Fatalf("Less(0, 1) = %t, want %t", got, tc.want)
			}
			if containers.Less(0, 0) || containers.Less(1, 1) {
				t.Fatal("a container cannot precede itself")
			}
			if containers.Less(0, 1) && containers.Less(1, 0) {
				t.Fatal("ordering must not place both containers before each other")
			}
		})
	}
}
