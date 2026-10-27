package observability

import "time"

func pushKind(kind string) string {
	return fixed(kind, "challenge", "approval", "question", "timed_question")
}

func (m *Metrics) PushSend(kind, result string, elapsed time.Duration) {
	if m != nil {
		m.pushSends.WithLabelValues(pushKind(kind), fixed(result, "provider_accepted", "retry", "invalid_endpoint", "failed", "expired")).Observe(elapsed.Seconds())
	}
}

func (m *Metrics) PushOperation(operation, result string, elapsed time.Duration) {
	if m != nil {
		m.pushOperations.WithLabelValues(fixed(operation, "complete", "receipt"), fixed(result, "ok", "access_denied", "expired", "lease", "conflict", "invalid", "cancelled", "timeout", "unavailable")).Observe(elapsed.Seconds())
	}
}

func (m *Metrics) PushDelivery(kind, state, code string, created, updated time.Time) {
	if m == nil {
		return
	}
	kind, state = pushKind(kind), fixed(state, "provider_accepted", "retry", "failed", "expired")
	if code == "" {
		code = "none"
	}
	code = fixed(code, "none", "authority_changed", "metadata_unavailable", "invalid_envelope", "expired", "provider_auth_unavailable", "provider_result_unknown", "provider_redirect", "provider_unregistered", "provider_throttled", "provider_unavailable", "provider_rejected")
	m.pushDeliveries.WithLabelValues(kind, state, code).Inc()
	m.pushAge("delivery", created, updated, m.pushDeliveryAge.WithLabelValues(kind, state).Observe)
}

func (m *Metrics) PushReceipt(kind, state string, created, recorded time.Time) {
	if m == nil {
		return
	}
	kind, state = pushKind(kind), fixed(state, "posted", "opened", "blocked")
	m.pushReceipts.WithLabelValues(kind, state).Inc()
	m.pushAge("receipt", created, recorded, m.pushReceiptAge.WithLabelValues(kind, state).Observe)
}

func (m *Metrics) pushAge(source string, created, recorded time.Time, observe func(float64)) {
	if created.IsZero() || recorded.IsZero() {
		return
	}
	elapsed := recorded.Sub(created)
	if elapsed < 0 {
		m.pushClock.WithLabelValues(source).Inc()
		return
	}
	observe(elapsed.Seconds())
}
