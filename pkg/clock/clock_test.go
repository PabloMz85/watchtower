package clock_test

import (
	"sync"
	"testing"
	"time"

	"github.com/PabloMz85/watchtower/pkg/clock"
)

func TestRealClockNow(t *testing.T) {
	var source clock.Clock = clock.RealClock{}

	before := time.Now()
	got := source.Now()
	after := time.Now()

	// Sub compares monotonic readings when both values have them.
	if got.Sub(before) < 0 || after.Sub(got) < 0 {
		t.Fatalf("Now() = %v, want a time between %v and %v", got, before, after)
	}
}

func TestRealClockConcurrentConsumers(t *testing.T) {
	var source clock.Clock = clock.RealClock{}
	var consumers sync.WaitGroup
	for range 8 {
		consumers.Go(func() {
			for range 100 {
				before := time.Now()
				got := source.Now()
				after := time.Now()
				if got.Sub(before) < 0 || after.Sub(got) < 0 {
					t.Errorf("Now() = %v, want a time between %v and %v", got, before, after)
				}
			}
		})
	}
	consumers.Wait()
}

func TestClockInstancesAreIndependent(t *testing.T) {
	first := &fakeClock{now: time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)}
	second := &fakeClock{now: first.now.Add(24 * time.Hour)}
	secondNow := second.now
	first.now = first.now.Add(time.Hour)

	// Each parallel consumer receives its own instance, not a shared setter.
	for _, tc := range []struct {
		name   string
		source clock.Clock
		want   time.Time
	}{
		{name: "advanced", source: first, want: first.now},
		{name: "unchanged", source: second, want: secondNow},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for range 100 {
				if got := tc.source.Now(); !got.Equal(tc.want) {
					t.Fatalf("Now() = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// fakeClock is deliberately test-local; production only supplies RealClock.
type fakeClock struct {
	now time.Time
}

func (f *fakeClock) Now() time.Time {
	return f.now
}
