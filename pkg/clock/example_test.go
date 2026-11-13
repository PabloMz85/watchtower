package clock_test

import (
	"fmt"
	"time"

	"github.com/PabloMz85/watchtower/pkg/clock"
)

func ExampleClock() {
	// A consumer accepts a clock instance alongside its other dependencies.
	expiresAt := func(source clock.Clock, ttl time.Duration) time.Time {
		return source.Now().Add(ttl)
	}

	// Tests can inject a private fake without changing any global state.
	source := &fakeClock{now: time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)}
	fmt.Println(expiresAt(source, 5*time.Minute).Format(time.RFC3339))
	// Output: 2026-01-01T00:05:00Z
}

func ExampleRealClock() {
	// The zero value is usable as an injected production dependency.
	var source clock.Clock = clock.RealClock{}
	fmt.Println(source.Now().IsZero())
	// Output: false
}
