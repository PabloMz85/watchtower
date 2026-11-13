# Instance-injected clock

This branch also pins the module, CI and source builders to Go 1.27.4 as an
approved prerequisite for GO-2026-6859. Publication triggers and destinations
are unchanged; the prerequisite is shared with the other feature branches.

`pkg/clock` exposes only `Clock` (`Now() time.Time`) and the stateless
`RealClock`, which delegates to `time.Now()`. Its zero value is ready to use.
The package uses only the standard library and has no global state, setters,
factories, or scheduling methods.

Consumers should receive a `clock.Clock` instance through their constructor and
store it on the owning instance. Production passes `clock.RealClock{}`; tests
supply a private fake. Separate consumers can then use independent times without
resetting a process-wide clock or interfering with parallel tests.

For example, a TTL consumer computes its deadline from the injected source:

```go
import (
    "time"

    "github.com/PabloMz85/watchtower/pkg/clock"
)

func expiresAt(source clock.Clock, ttl time.Duration) time.Time {
    return source.Now().Add(ttl)
}
```

The executable examples in `pkg/clock/example_test.go` demonstrate production
injection and deterministic TTL calculation with a test-only fake, without
sleeping. RealClock tests bound each result by surrounding `time.Now()` calls,
using monotonic comparisons, and exercise concurrent consumers under the race
detector.

This branch supplies the small working library for the next stacked TokenCache
branch, which will add the actual cache consumer and inject its TTL clock. It
introduces no cache/backend stubs. No existing package-global `now` variable was
replaced: the current fork has none to migrate. Existing sleep, scheduling,
preview, SDK, flags, and publication behavior remain unchanged.
