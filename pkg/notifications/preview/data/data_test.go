package data

import (
	"encoding/hex"
	"slices"
	"strings"
	"testing"

	"github.com/PabloMz85/watchtower/pkg/types"
)

func TestStatesFromString(t *testing.T) {
	for _, tt := range []struct {
		name, input string
		want        []State
	}{
		{"empty", "", []State{}},
		{"all", "cuektf", []State{ScannedState, UpdatedState, FailedState, SkippedState, StaleState, FreshState}},
		{"order and duplicates", "fuucec", []State{FreshState, UpdatedState, UpdatedState, ScannedState, FailedState, ScannedState}},
		{"ignore unknown selectors", "?C U!é🙂\ncu", []State{ScannedState, UpdatedState}},
		{"only unknown selectors", "xyz 123", []State{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := StatesFromString(tt.input); !slices.Equal(got, tt.want) {
				t.Fatalf("StatesFromString(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestLevelsFromString(t *testing.T) {
	for _, tt := range []struct {
		name, input string
		want        []LogLevel
	}{
		{"empty", "", []LogLevel{}},
		{"all", "pfewidt", []LogLevel{PanicLevel, FatalLevel, ErrorLevel, WarnLevel, InfoLevel, DebugLevel, TraceLevel}},
		{"order and duplicates", "dtti", []LogLevel{DebugLevel, TraceLevel, TraceLevel, InfoLevel}},
		{"ignore unknown selectors", "?P W!é🙂\nti", []LogLevel{TraceLevel, InfoLevel}},
		{"only unknown selectors", "xyz 123", []LogLevel{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := LevelsFromString(tt.input); !slices.Equal(got, tt.want) {
				t.Fatalf("LevelsFromString(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
	for _, level := range []LogLevel{TraceLevel, DebugLevel, InfoLevel, WarnLevel, ErrorLevel, FatalLevel, PanicLevel, LogLevel("custom")} {
		if got := level.String(); got != string(level) {
			t.Errorf("%q.String() = %q", level, got)
		}
	}
	if WarnLevel.String() != "warning" {
		t.Errorf("warning level = %q, want warning", WarnLevel.String())
	}
}

func reportCategories(r types.Report) map[State][]types.ContainerReport {
	return map[State][]types.ContainerReport{
		ScannedState: r.Scanned(), UpdatedState: r.Updated(), FailedState: r.Failed(),
		SkippedState: r.Skipped(), StaleState: r.Stale(), FreshState: r.Fresh(),
	}
}

func TestGeneratedContainersPopulateCategoriesAndConsistentFields(t *testing.T) {
	p := New()
	if len(p.Entries) != 0 || p.StaticData.Title != "Title" || p.StaticData.Host != "Host" {
		t.Fatalf("unexpected initial preview: entries=%v static=%+v", p.Entries, p.StaticData)
	}
	states := []State{ScannedState, UpdatedState, FailedState, SkippedState, StaleState, FreshState}
	for range 2 {
		for _, state := range states {
			p.AddFromState(state)
		}
	}
	seenIDs := map[string]bool{}
	seenNames := map[string]bool{}
	for state, containers := range reportCategories(p.Report()) {
		if len(containers) != 2 {
			t.Fatalf("%s category has %d containers, want 2", state, len(containers))
		}
		for _, c := range containers {
			if c.State() != string(state) {
				t.Errorf("%s category contains state %q", state, c.State())
			}
			for _, id := range []string{string(c.ID()), string(c.CurrentImageID()), string(c.LatestImageID())} {
				decoded, err := hex.DecodeString(id)
				if err != nil || len(decoded) != 32 {
					t.Errorf("ID %q is not a 32-byte hexadecimal identifier: %v", id, err)
				}
				if seenIDs[id] {
					t.Errorf("duplicate generated ID %q", id)
				}
				seenIDs[id] = true
			}
			name := c.Name()
			if !strings.HasPrefix(name, "/") || len(name) <= 1 || strings.ContainsAny(name, " \t\n") || seenNames[name] {
				t.Errorf("invalid or repeated container name %q", name)
			}
			seenNames[name] = true
			organization, image, ok := strings.Cut(c.ImageName(), "/")
			if !ok || organization == "" || image != strings.TrimPrefix(name, "/")+":latest" {
				t.Errorf("image %q does not match container name %q", c.ImageName(), name)
			}
			wantError := state == FailedState || state == SkippedState
			if (c.Error() != "") != wantError {
				t.Errorf("%s container error = %q, want nonempty=%v", state, c.Error(), wantError)
			}
		}
	}
	all := p.Report().All()
	if len(all) != 12 {
		t.Fatalf("All() has %d containers, want 12", len(all))
	}
	for i := 1; i < len(all); i++ {
		if all[i-1].ID() >= all[i].ID() {
			t.Errorf("All() is not ordered by unique ID at index %d", i)
		}
	}
}

func TestUnknownStateDoesNotAddAReportEntry(t *testing.T) {
	for _, knownFirst := range []bool{false, true} {
		p := New()
		if knownFirst {
			p.AddFromState(UpdatedState)
		}
		p.AddFromState(State("unknown"))
		want := 0
		if knownFirst {
			want = 1
		}
		if got := len(p.Report().All()); got != want {
			t.Errorf("knownFirst=%v: All() has %d containers, want %d", knownFirst, got, want)
		}
	}
}

func TestLogEntriesPreserveLevelsAndHaveMonotonicTimes(t *testing.T) {
	p := New()
	levels := []LogLevel{TraceLevel, DebugLevel, InfoLevel, WarnLevel, ErrorLevel, FatalLevel, PanicLevel, LogLevel("custom")}
	for range 2 {
		for _, level := range levels {
			p.AddLogEntry(level)
		}
	}
	if len(p.Entries) != 2*len(levels) {
		t.Fatalf("got %d log entries, want %d", len(p.Entries), 2*len(levels))
	}
	for i, entry := range p.Entries {
		if entry.Level != levels[i%len(levels)] {
			t.Errorf("entry %d level = %q, want %q", i, entry.Level, levels[i%len(levels)])
		}
		if entry.Message == "" || entry.Data == nil || len(entry.Data) != 0 {
			t.Errorf("entry %d has unexpected message/data: %+v", i, entry)
		}
		if entry.Time.IsZero() || (i > 0 && entry.Time.Before(p.Entries[i-1].Time)) {
			t.Errorf("entry %d has zero or decreasing timestamp %v", i, entry.Time)
		}
	}
}
