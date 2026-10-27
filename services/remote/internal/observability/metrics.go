// Package observability exposes bounded operational metadata, never resource IDs
// or caller-supplied text. Each service owns a private Prometheus registry.
package observability

import (
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var durationBuckets = []float64{.001, .005, .01, .025, .05, .1, .25, .3, .5, 1, 2, 5, 10}

type Metrics struct {
	registry                  *prometheus.Registry
	receivedFrames            *prometheus.CounterVec
	receivedBytes             *prometheus.CounterVec
	writtenFrames             *prometheus.CounterVec
	writtenBytes              *prometheus.CounterVec
	writeDuration             *prometheus.HistogramVec
	queueDuration             *prometheus.HistogramVec
	routeDuration             prometheus.Histogram
	rejectedSends             *prometheus.CounterVec
	protocolErrors            *prometheus.CounterVec
	resyncs                   prometheus.Counter
	forwards                  *prometheus.HistogramVec
	revocations               *prometheus.CounterVec
	controlRuns               *prometheus.HistogramVec
	controlReady              *prometheus.GaugeVec
	controlSuccess            *prometheus.GaugeVec
	controlEvents             *prometheus.CounterVec
	controlAge                *prometheus.HistogramVec
	clockSkew                 prometheus.Counter
	tunnelDuration            *prometheus.HistogramVec
	commandTransitions        *prometheus.CounterVec
	commandAge                *prometheus.HistogramVec
	commandDwell              *prometheus.HistogramVec
	commandStore              *prometheus.HistogramVec
	commandClock              *prometheus.CounterVec
	native                    *nativeCollector
	nativeReports             *prometheus.CounterVec
	approvalStates            *prometheus.CounterVec
	approvalHosts             *prometheus.CounterVec
	approvalOps               *prometheus.HistogramVec
	approvalLeasePrepared     *prometheus.CounterVec
	approvalLeaseLifetime     *prometheus.HistogramVec
	approvalLeaseRemaining    *prometheus.HistogramVec
	approvalLeaseAvailability *prometheus.CounterVec
	fileScans                 *prometheus.HistogramVec
	fileHandoffOperations     *prometheus.HistogramVec
	fileHandoffEvents         *prometheus.CounterVec
	fileHandoffAge            *prometheus.HistogramVec
	fileHandoffStage          prometheus.Histogram
	fileClock                 *prometheus.CounterVec
	pushSends                 *prometheus.HistogramVec
	pushOperations            *prometheus.HistogramVec
	pushDeliveries            *prometheus.CounterVec
	pushReceipts              *prometheus.CounterVec
	pushDeliveryAge           *prometheus.HistogramVec
	pushReceiptAge            *prometheus.HistogramVec
	pushClock                 *prometheus.CounterVec
}

func New() *Metrics {
	counter := func(name, help string, labels ...string) *prometheus.CounterVec {
		return prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "dsh_remote", Name: name, Help: help}, labels)
	}
	histogram := func(name, help string, labels ...string) *prometheus.HistogramVec {
		return prometheus.NewHistogramVec(prometheus.HistogramOpts{Namespace: "dsh_remote", Name: name, Help: help, Buckets: durationBuckets}, labels)
	}
	m := &Metrics{
		pushSends:                 histogram("push_provider_send_duration_seconds", "FCM sender attempt duration including OAuth, authority recheck and response handling; result is not database commit or phone display.", "kind", "result"),
		pushOperations:            histogram("push_operation_duration_seconds", "Push completion or client-receipt repository attempt duration including authorization, audit and commit; includes retries and failures.", "operation", "result"),
		pushDeliveries:            counter("push_delivery_results_total", "Delivery completion results with confirmed commit, including distinct retry attempts; not phone display.", "kind", "state", "code"),
		pushReceipts:              counter("push_client_receipts_total", "New committed authenticated client posted/opened/blocked reports, once per notification/state; not proof a human saw a notification.", "kind", "state"),
		pushDeliveryAge:           prometheus.NewHistogramVec(prometheus.HistogramOpts{Namespace: "dsh_remote", Name: "push_delivery_age_seconds", Help: "Database time from delivery creation to committed completion update; includes queue/retry time and excludes later commit wait.", Buckets: []float64{.01, .1, 1, 5, 10, 30, 60, 120, 300, 600, 3600}}, []string{"kind", "state"}),
		pushReceiptAge:            prometheus.NewHistogramVec(prometheus.HistogramOpts{Namespace: "dsh_remote", Name: "push_client_receipt_age_seconds", Help: "Database time from delivery creation to newly committed client-receipt insertion; not provider-to-display latency.", Buckets: []float64{.01, .1, 1, 5, 10, 30, 60, 120, 300, 600, 3600, 86400}}, []string{"kind", "state"}),
		pushClock:                 counter("push_clock_anomalies_total", "Negative database age intervals excluded from push duration observations.", "source"),
		fileScans:                 prometheus.NewHistogramVec(prometheus.HistogramOpts{Namespace: "dsh_remote", Name: "file_scan_attempt_duration_seconds", Help: "Claimed worker scan attempt duration, including object verification, scanning, copy and repository completion/failure handling; not queue or upload time.", Buckets: []float64{.001, .01, .1, .5, 1, 2, 5, 10, 30, 60, 120, 300, 900}}, []string{"direction", "result"}),
		fileHandoffOperations:     histogram("file_handoff_operation_duration_seconds", "Handoff repository attempt duration including authorization, locks and commit; includes no-op retries and failures.", "operation", "result"),
		fileHandoffEvents:         counter("file_handoff_events_total", "Selected handoff milestones with confirmed commit; staged is a Host report, not native admission or execution.", "stage"),
		fileHandoffAge:            prometheus.NewHistogramVec(prometheus.HistogramOpts{Namespace: "dsh_remote", Name: "file_handoff_age_seconds", Help: "Database time from offer creation to committed read-start or staged update; excludes later commit confirmation and native admission.", Buckets: []float64{.001, .01, .1, .5, 1, 2, 5, 10, 30, 60, 120, 300}}, []string{"stage"}),
		fileHandoffStage:          prometheus.NewHistogram(prometheus.HistogramOpts{Namespace: "dsh_remote", Name: "file_handoff_read_to_stage_seconds", Help: "Database time from read-ticket consumption to first committed Host staged acknowledgement; not independently verified Host durability or native admission.", Buckets: []float64{.001, .01, .1, .5, 1, 2, 5, 10, 30, 60, 120, 300}}),
		fileClock:                 counter("file_clock_anomalies_total", "Committed handoff timestamps with negative database intervals, excluded from duration observations.", "stage"),
		approvalStates:            counter("approval_state_transitions_total", "Approval control state changes whose commit this process confirmed; allowed alone is not execution completion.", "from", "to", "cause"),
		approvalHosts:             counter("approval_host_transitions_total", "Committed Host journal fact changes; consumption and settled execution outcome remain distinct.", "from", "to", "outcome"),
		approvalOps:               histogram("approval_operation_duration_seconds", "Approval repository/provider attempt duration including validation, authorization, locks, signing and commit; includes retries.", "operation", "result"),
		approvalLeasePrepared:     counter("approval_lease_preparations_total", "Signed authorization preparations with confirmed audit/outbox commit; not delivery or execution.", "decision"),
		approvalLeaseLifetime:     prometheus.NewHistogramVec(prometheus.HistogramOpts{Namespace: "dsh_remote", Name: "approval_lease_lifetime_seconds", Help: "Committed signed lease expires_at minus issued_at, clipped to original authority deadlines.", Buckets: []float64{.001, .01, .05, .1, .25, .5, 1, 2, 3}}, []string{"decision"}),
		approvalLeaseRemaining:    prometheus.NewHistogramVec(prometheus.HistogramOpts{Namespace: "dsh_remote", Name: "approval_lease_remaining_seconds", Help: "Positive signed expiry minus process wall clock at the post-commit availability check; not a delivery guarantee.", Buckets: []float64{.001, .01, .05, .1, .25, .5, 1, 2, 3}}, []string{"decision"}),
		approvalLeaseAvailability: counter("approval_lease_availability_checks_total", "Post-commit signed lease availability checks; a proof can still expire before return or delivery.", "decision", "result"),
		native:                    newNativeCollector(),
		nativeReports:             counter("host_observation_reports_total", "Connection-scoped Host observation report validation outcomes.", "result"),
		registry:                  prometheus.NewRegistry(),
		receivedFrames:            counter("relay_received_frames_total", "Complete received WebSocket data messages, including rejected messages.", "role"),
		receivedBytes:             counter("relay_received_bytes_total", "Payload bytes of complete received WebSocket data messages.", "role"),
		writtenFrames:             counter("relay_written_frames_total", "WebSocket data messages whose write completed successfully.", "role"),
		writtenBytes:              counter("relay_written_bytes_total", "Payload bytes of successfully written WebSocket data messages.", "role"),
		writeDuration:             histogram("relay_send_duration_seconds", "Time from enqueue attempt to writer completion, including queue and recipient write time; excludes native execution.", "role", "result"),
		queueDuration:             histogram("relay_queue_duration_seconds", "Time from enqueue attempt until the writer dequeues the message; excludes socket I/O.", "role"),
		routeDuration:             prometheus.NewHistogram(prometheus.HistogramOpts{Namespace: "dsh_remote", Name: "relay_session_route_duration_seconds", Help: "Successfully routed session data message: complete Go ingress read to destination write, including decoding, authorization and queuing; excludes TLS ingress and native execution.", Buckets: durationBuckets}),
		rejectedSends:             counter("relay_rejected_sends_total", "Outgoing messages rejected before queue admission.", "role", "reason"),
		protocolErrors:            counter("relay_protocol_errors_total", "Protocol error responses attempted, grouped into fixed error classes.", "class"),
		resyncs: prometheus.NewCounter(prometheus.CounterOpts{Namespace: "dsh_remote", Name: "relay_resyncs_total",
			Help: "Resync-required errors or subscription invalidations; not unique sessions."}),
		forwards:    histogram("command_forward_duration_seconds", "Recorded-command forwarding and receipt handling time; excludes initial persistence and native execution.", "result"),
		revocations: counter("relay_revoked_connections_total", "Connections fenced by authority invalidation, counted once per connection.", "role", "reason"),
		controlRuns: histogram("control_run_duration_seconds", "Local control worker attempt duration.", "worker", "result"),
		controlReady: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: "dsh_remote", Name: "control_available",
			Help: "One after the worker's most recent successful attempt; zero on failure or before its first success."}, []string{"worker"}),
		controlSuccess: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: "dsh_remote", Name: "control_last_success_timestamp_seconds",
			Help: "Unix timestamp of the most recent successful worker attempt, or zero."}, []string{"worker"}),
		controlEvents: counter("control_events_total", "Local outbox apply/publication attempts; retries can observe an event more than once.", "topic", "result"),
		controlAge: prometheus.NewHistogramVec(prometheus.HistogramOpts{Namespace: "dsh_remote", Name: "control_event_age_seconds",
			Help:    "Database creation to local apply and publication acknowledgement; not remote execution or multi-node fanout latency.",
			Buckets: []float64{.01, .1, .25, .5, 1, 2, 5, 10, 30, 60, 300, 3600}}, []string{"topic"}),
		clockSkew: prometheus.NewCounter(prometheus.CounterOpts{Namespace: "dsh_remote", Name: "control_event_future_timestamps_total",
			Help: "Published events with future database timestamps, excluded from the age histogram."}),
		tunnelDuration:     histogram("relay_tunnel_transit_duration_seconds", "One proxy leg from complete message read to completed destination write; excludes owner authorization and the other leg.", "direction", "result"),
		commandTransitions: counter("command_transitions_total", "New command rows or state changes whose database commit this process confirmed; retries of unchanged state do not count.", "action", "from", "to", "origin"),
		commandAge:         prometheus.NewHistogramVec(prometheus.HistogramOpts{Namespace: "dsh_remote", Name: "command_state_entry_age_seconds", Help: "Database updated_at minus command created_at on each committed state change; includes native/network/wait time and later re-entries, not first-accept latency.", Buckets: commandTimeBuckets}, []string{"action", "state"}),
		commandDwell:       prometheus.NewHistogramVec(prometheus.HistogramOpts{Namespace: "dsh_remote", Name: "command_state_dwell_seconds", Help: "Database updated_at minus previous updated_at on a committed state change; not native execution duration.", Buckets: commandTimeBuckets}, []string{"action", "from", "to"}),
		commandStore:       histogram("command_store_duration_seconds", "Monotonic command repository call duration including validation, authorization, lock waits and commit; all attempts, including unchanged retries.", "operation", "result"),
		commandClock:       counter("command_timestamp_anomalies_total", "Missing or backward database timestamps excluded from command age/dwell histograms.", "interval"),
	}
	m.Register(m.fileScans, m.fileHandoffOperations, m.fileHandoffEvents, m.fileHandoffAge, m.fileHandoffStage, m.fileClock)
	m.Register(m.pushSends, m.pushOperations, m.pushDeliveries, m.pushReceipts, m.pushDeliveryAge, m.pushReceiptAge, m.pushClock)
	m.Register(m.receivedFrames, m.receivedBytes, m.writtenFrames, m.writtenBytes, m.writeDuration, m.queueDuration, m.routeDuration, m.rejectedSends,
		m.protocolErrors, m.resyncs, m.forwards, m.revocations, m.controlRuns, m.controlReady, m.controlSuccess,
		m.controlEvents, m.controlAge, m.clockSkew, m.tunnelDuration, m.commandTransitions, m.commandAge, m.commandDwell, m.commandStore, m.commandClock, m.native, m.nativeReports, m.approvalStates, m.approvalHosts, m.approvalOps, m.approvalLeasePrepared, m.approvalLeaseLifetime, m.approvalLeaseRemaining, m.approvalLeaseAvailability, collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	for _, role := range []string{"installation", "device", "other"} {
		m.receivedFrames.WithLabelValues(role)
		m.receivedBytes.WithLabelValues(role)
		m.writtenFrames.WithLabelValues(role)
		m.writtenBytes.WithLabelValues(role)
	}
	for _, worker := range []string{"outbox", "leases", "consumer", "consumer_cleanup"} {
		m.controlReady.WithLabelValues(worker).Set(0)
		m.controlSuccess.WithLabelValues(worker).Set(0)
	}
	for _, result := range []string{"accepted", "duplicate", "rejected", "throttled", "denied"} {
		m.nativeReports.WithLabelValues(result)
	}
	return m
}

func (m *Metrics) Register(collectors ...prometheus.Collector) {
	if m != nil {
		m.registry.MustRegister(collectors...)
	}
}

func (m *Metrics) Gatherer() prometheus.Gatherer { return m.registry }

func (m *Metrics) Handler() http.Handler {
	mux := http.NewServeMux()
	handler := promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{MaxRequestsInFlight: 2, Timeout: 2 * time.Second, DisableCompression: true, CoalesceGather: true})
	mux.Handle("GET /metrics", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		handler.ServeHTTP(w, r)
	}))
	return mux
}

func Role(value string) string {
	if value == "installation" || value == "device" {
		return value
	}
	return "other"
}

func fixed(value string, allowed ...string) string {
	for _, item := range allowed {
		if value == item {
			return item
		}
	}
	return "other"
}

func (m *Metrics) Received(role string, bytes int) {
	if m == nil {
		return
	}
	role = Role(role)
	m.receivedFrames.WithLabelValues(role).Inc()
	m.receivedBytes.WithLabelValues(role).Add(float64(bytes))
}

func (m *Metrics) Written(role string, bytes int, elapsed time.Duration, err error) {
	if m == nil {
		return
	}
	role, result := Role(role), "error"
	if err == nil {
		result = "written"
		m.writtenFrames.WithLabelValues(role).Inc()
		m.writtenBytes.WithLabelValues(role).Add(float64(bytes))
	}
	m.writeDuration.WithLabelValues(role, result).Observe(elapsed.Seconds())
}

func (m *Metrics) Dequeued(role string, elapsed time.Duration) {
	if m != nil {
		m.queueDuration.WithLabelValues(Role(role)).Observe(elapsed.Seconds())
	}
}

func (m *Metrics) RoutedSession(elapsed time.Duration) {
	if m != nil {
		m.routeDuration.Observe(elapsed.Seconds())
	}
}

func (m *Metrics) TunnelTransit(direction int, elapsed time.Duration, err error) {
	if m == nil {
		return
	}
	label, result := "phone_to_owner", "written"
	if direction == 1 {
		label = "owner_to_phone"
	}
	if err != nil {
		result = "error"
	}
	m.tunnelDuration.WithLabelValues(label, result).Observe(elapsed.Seconds())
}

func (m *Metrics) RejectedSend(role, reason string) {
	if m == nil {
		return
	}
	m.rejectedSends.WithLabelValues(Role(role), fixed(reason, "serialization", "too_large", "closed", "cancelled", "full")).Inc()
}

func (m *Metrics) ProtocolError(code string) {
	if m == nil {
		return
	}
	class := "other"
	switch {
	case code == "rate.limited":
		class = "rate_limited"
	case code == "internal":
		class = "internal"
	case strings.HasPrefix(code, "protocol."):
		class = "protocol"
	case strings.HasPrefix(code, "access."):
		class = "access"
	case strings.HasPrefix(code, "runtime."):
		class = "runtime"
	case strings.HasPrefix(code, "command."):
		class = "command"
	case strings.HasPrefix(code, "file."):
		class = "file"
	}
	m.protocolErrors.WithLabelValues(class).Inc()
	if code == "protocol.resync_required" {
		m.Resync()
	}
}

func (m *Metrics) Resync() {
	if m != nil {
		m.resyncs.Inc()
	}
}

func (m *Metrics) Forward(result string, elapsed time.Duration) {
	if m == nil {
		return
	}
	m.forwards.WithLabelValues(fixed(result, "denied", "forwarded", "duplicate", "queue_full", "unknown", "reconcile_unavailable")).Observe(elapsed.Seconds())
}

func (m *Metrics) Revoked(role, reason string) {
	if m == nil {
		return
	}
	m.revocations.WithLabelValues(Role(role), fixed(reason, "access_revoked", "authority_unavailable")).Inc()
}

func (m *Metrics) ControlRun(worker, result string, elapsed time.Duration) {
	if m == nil {
		return
	}
	worker, result = fixed(worker, "outbox", "leases", "consumer", "consumer_cleanup"), fixed(result, "ok", "error", "cancelled")
	m.controlRuns.WithLabelValues(worker, result).Observe(elapsed.Seconds())
	if result == "ok" {
		m.controlReady.WithLabelValues(worker).Set(1)
		m.controlSuccess.WithLabelValues(worker).Set(float64(time.Now().UnixNano()) / 1e9)
	} else if result == "error" {
		m.controlReady.WithLabelValues(worker).Set(0)
	}
}

func (m *Metrics) ControlEvent(topic, result string, created time.Time) {
	if m == nil {
		return
	}
	topic = fixed(topic, "device.revoked", "runtime_grant.updated", "runtime_grant.revoked", "approval.pending", "approval.decided",
		"approval.ended", "approval.result", "approval.authorization.prepared", "approval.device.revoked")
	result = fixed(result, "published", "apply_error", "ack_error")
	m.controlEvents.WithLabelValues(topic, result).Inc()
	if result == "published" && !created.IsZero() {
		if age := time.Since(created); age >= 0 {
			m.controlAge.WithLabelValues(topic).Observe(age.Seconds())
		} else {
			m.clockSkew.Inc()
		}
	}
}
