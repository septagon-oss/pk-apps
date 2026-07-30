// Implements: REQ-016.
// Per: ADR-0017.
// Discipline: C-14.

package pollmodule

import "expvar"

var pollMetrics = expvar.NewMap("platformkit_poll")

func addMetric(name string, delta int64) {
	pollMetrics.Add(name, delta)
}
