// Package clock provides an instance-injected source of the current time.
package clock

import "time"

// Clock supplies the current time.
type Clock interface {
	Now() time.Time
}

// RealClock is a stateless Clock whose zero value is ready to use.
type RealClock struct{}

// Now returns the current local time using time.Now.
func (RealClock) Now() time.Time {
	return time.Now()
}
