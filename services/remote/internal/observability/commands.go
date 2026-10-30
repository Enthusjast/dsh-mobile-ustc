package observability

import "time"

var commandTimeBuckets = []float64{.001, .005, .01, .05, .1, .3, .5, 1, 2, 5, 10, 30, 60, 120, 300, 900, 1800}

func commandAction(action string) string {
	return fixed(action, "message.submit", "session.create", "session.cancel", "session.archive", "session.model.select", "question.answer")
}
func commandState(state string) string {
	return fixed(state, "none", "received", "host_accepted", "dispatching", "agent_queued", "observed", "settled", "rejected", "outcome_unknown")
}

// Called only after a database commit was confirmed, never on send/broadcast.
// These are local process observations; audit/state remain the durable truth.
func (m *Metrics) CommandTransition(action, from, to, origin string, created, previous, entered time.Time) {
	if m == nil {
		return
	}
	action, from, to, origin = commandAction(action), commandState(from), commandState(to), fixed(origin, "device", "host", "relay")
	m.commandTransitions.WithLabelValues(action, from, to, origin).Inc()
	if from == "none" {
		return
	}
	if created.IsZero() || entered.IsZero() || entered.Before(created) {
		m.commandClock.WithLabelValues("age").Inc()
	} else {
		m.commandAge.WithLabelValues(action, to).Observe(entered.Sub(created).Seconds())
	}
	if previous.IsZero() || entered.IsZero() || entered.Before(previous) {
		m.commandClock.WithLabelValues("dwell").Inc()
	} else {
		m.commandDwell.WithLabelValues(action, from, to).Observe(entered.Sub(previous).Seconds())
	}
}

func (m *Metrics) CommandStore(operation, result string, elapsed time.Duration) {
	if m == nil {
		return
	}
	m.commandStore.WithLabelValues(fixed(operation, "admit", "create", "file_admit", "receipt", "unknown"), fixed(result, "ok", "denied", "conflict", "invalid", "not_ready", "limited", "cancelled", "error")).Observe(elapsed.Seconds())
}
