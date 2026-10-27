package observability

import "time"

func approvalState(state string) string {
	if state == "" {
		state = "none"
	}
	return fixed(state, "none", "pending", "decision_received", "allowed", "denied", "expired", "cancelled", "invalidated", "outcome_unknown")
}
func approvalHostState(state string) string {
	if state == "" {
		state = "none"
	}
	return fixed(state, "none", "approved", "consumed", "settled", "denied", "expired", "cancelled", "invalidated", "outcome_unknown")
}
func approvalOutcome(outcome string) string {
	if outcome == "" {
		outcome = "none"
	}
	return fixed(outcome, "none", "succeeded", "failed", "cancelled")
}

// Only confirmed committed changes, never references, broadcasts or signatures
// alone. Control state and reported Host facts intentionally remain separate.
func (m *Metrics) ApprovalTransition(cause, from, to, fromHost, toHost, outcome string) {
	if m == nil {
		return
	}
	cause = fixed(cause, "registration", "decision", "host_result", "expiry", "connection")
	from, to = approvalState(from), approvalState(to)
	fromHost, toHost = approvalHostState(fromHost), approvalHostState(toHost)
	if from != to {
		m.approvalStates.WithLabelValues(from, to, cause).Inc()
	}
	if fromHost != toHost {
		m.approvalHosts.WithLabelValues(fromHost, toHost, approvalOutcome(outcome)).Inc()
	}
}
func (m *Metrics) ApprovalOperation(operation, result string, elapsed time.Duration) {
	if m != nil {
		m.approvalOps.WithLabelValues(fixed(operation, "register", "decide", "host_result", "lease"), fixed(result, "ok", "denied", "expired", "conflict", "invalid", "cancelled", "error")).Observe(elapsed.Seconds())
	}
}
func (m *Metrics) ApprovalLeasePrepared(decision string, lifetime time.Duration) {
	if m == nil {
		return
	}
	decision = fixed(decision, "allow_once", "reject")
	m.approvalLeasePrepared.WithLabelValues(decision).Inc()
	if lifetime > 0 {
		m.approvalLeaseLifetime.WithLabelValues(decision).Observe(lifetime.Seconds())
	}
}
func (m *Metrics) ApprovalLeaseAvailability(decision string, remaining time.Duration) {
	if m == nil {
		return
	}
	decision = fixed(decision, "allow_once", "reject")
	result := "available"
	if remaining <= 0 {
		result = "expired"
	} else {
		m.approvalLeaseRemaining.WithLabelValues(decision).Observe(remaining.Seconds())
	}
	m.approvalLeaseAvailability.WithLabelValues(decision, result).Inc()
}
