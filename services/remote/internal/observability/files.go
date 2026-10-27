package observability

import "time"

func (m *Metrics) FileScanAttempt(direction, result string, elapsed time.Duration) {
	if m != nil {
		m.fileScans.WithLabelValues(fixed(direction, "to_host", "from_host"),
			fixed(result, "clean", "access_denied", "stale", "rejected", "integrity", "scanner_unavailable", "invalid", "cancelled", "timeout", "unavailable")).Observe(elapsed.Seconds())
	}
}

func (m *Metrics) FileHandoffOperation(operation, result string, elapsed time.Duration) {
	if m != nil {
		m.fileHandoffOperations.WithLabelValues(fixed(operation, "offer", "read", "stage", "renew", "end"),
			fixed(result, "ok", "access_denied", "stale", "conflict", "quota", "invalid", "cancelled", "timeout", "unavailable")).Observe(elapsed.Seconds())
	}
}

// A milestone is observed only after its outer commit is confirmed. Timestamps
// share the database clock and describe the update, not commit confirmation.
func (m *Metrics) FileHandoffMilestone(stage string, created, readStarted, updated time.Time) {
	if m == nil {
		return
	}
	stage = fixed(stage, "offered", "read_started", "staged")
	m.fileHandoffEvents.WithLabelValues(stage).Inc()
	if stage != "read_started" && stage != "staged" {
		return
	}
	observe := func(start time.Time, record func(float64)) {
		if start.IsZero() || updated.IsZero() {
			return
		}
		elapsed := updated.Sub(start)
		if elapsed < 0 {
			m.fileClock.WithLabelValues(stage).Inc()
			return
		}
		record(elapsed.Seconds())
	}
	observe(created, m.fileHandoffAge.WithLabelValues(stage).Observe)
	if stage == "staged" {
		observe(readStarted, m.fileHandoffStage.Observe)
	}
}
