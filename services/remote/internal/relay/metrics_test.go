package relay

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/observability"
	"dsh-mobile-ustc/services/remote/internal/store"
	dto "github.com/prometheus/client_model/go"
)

func metricsSnapshot(t *testing.T, m *observability.Metrics) map[string]*dto.MetricFamily {
	t.Helper()
	families, err := m.Gatherer().Gather()
	if err != nil {
		t.Fatal(err)
	}
	result := make(map[string]*dto.MetricFamily, len(families))
	for _, family := range families {
		result[family.GetName()] = family
	}
	return result
}

func metricValue(t *testing.T, snapshot map[string]*dto.MetricFamily, name string, labels map[string]string) float64 {
	t.Helper()
	for _, metric := range snapshot["dsh_remote_"+name].GetMetric() {
		if len(metric.Label) != len(labels) {
			continue
		}
		matches := true
		for _, label := range metric.Label {
			if labels[label.GetName()] != label.GetValue() {
				matches = false
			}
		}
		if matches {
			if metric.Gauge != nil {
				return metric.Gauge.GetValue()
			}
			if metric.Counter != nil {
				return metric.Counter.GetValue()
			}
		}
	}
	t.Fatalf("missing metric %s with labels %v", name, labels)
	return 0
}

func metricUntil(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("metrics test condition did not settle")
}

func TestQueueAccountingRetainsCancelledMessagesUntilActualWriterDrain(t *testing.T) {
	key := relayTestKey(t)
	jwk, jkt := relayTestPublicJWK(t, key)
	const installation = "11111111-1111-4111-8111-111111111111"
	const runtime = "33333333-3333-4333-8333-333333333333"
	const epoch = "44444444-4444-4444-8444-444444444444"
	fake := &relayTestStore{hostCredential: store.HostCredentialIdentity{InstallationID: installation, KeyVersion: 1, PublicJWK: jwk, KeyThumbprint: jkt, ExpiresAt: time.Now().Add(time.Minute)}, detached: make(chan store.RuntimeConnection, 1)}
	relay := New(fake)
	m := observability.New()
	relay.ConfigureMetrics(m)
	server := httptest.NewServer(relay)
	t.Cleanup(server.Close)
	host := dialRelayHost(t, server.URL, key, installation, runtime, epoch)
	defer host.CloseNow()
	live := relay.hostForRuntime(runtime)
	metricUntil(t, func() bool {
		live.queueMu.Lock()
		defer live.queueMu.Unlock()
		return live.queuedBytes == 0 && live.inflightBytes == 0
	})
	metricUntil(t, func() bool {
		return metricValue(t, metricsSnapshot(t, m), "relay_written_frames_total", map[string]string{"role": "installation"}) == 2
	})
	before := metricValue(t, metricsSnapshot(t, m), "relay_written_frames_total", map[string]string{"role": "installation"})
	const marker = "PRIVATE_QUEUE_BODY_MARKER"
	payload := map[string]any{"v": 1, "type": "metrics.fixture", "payload": map[string]string{"marker": marker}}
	encoded, _ := json.Marshal(payload)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	started, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- live.sendJSONBeforeWrite(ctx, payload, func() error { close(started); <-release; return nil })
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("writer did not start")
	}
	queuedCtx, cancelQueued := context.WithCancel(ctx)
	defer cancelQueued()
	queuedDone := make(chan error, cap(live.sendQueue))
	for range cap(live.sendQueue) {
		go func() { queuedDone <- live.sendJSON(queuedCtx, payload) }()
	}
	metricUntil(t, func() bool { live.queueMu.Lock(); defer live.queueMu.Unlock(); return live.queuedMessages == 16 })
	if err := live.sendJSON(ctx, payload); !errors.Is(err, errRelayQueueFull) {
		t.Fatal("full queue was not rejected", err)
	}
	cancelQueued()
	for range cap(live.sendQueue) {
		select {
		case err := <-queuedDone:
			if !errors.Is(err, context.Canceled) {
				t.Fatal("queued sender did not observe cancellation", err)
			}
		case <-ctx.Done():
			t.Fatal("cancelled send did not finish")
		}
	}
	snapshot := metricsSnapshot(t, m)
	role := map[string]string{"role": "installation"}
	for name, want := range map[string]float64{"relay_queued_messages": 16, "relay_queued_bytes": float64(16 * len(encoded)), "relay_inflight_bytes": float64(len(encoded)), "relay_max_connection_queued_bytes": float64(16 * len(encoded))} {
		if got := metricValue(t, snapshot, name, role); got != want {
			t.Fatalf("%s=%v, want %v", name, got, want)
		}
	}
	if metricValue(t, snapshot, "relay_rejected_sends_total", map[string]string{"role": "installation", "reason": "full"}) != 1 ||
		metricValue(t, snapshot, "relay_queued_connections", map[string]string{"role": "installation", "bytes_le": "0"}) != 0 ||
		metricValue(t, snapshot, "relay_queued_connections", map[string]string{"role": "installation", "bytes_le": "+Inf"}) != 1 {
		t.Fatal("queue rejection or current distribution was miscounted")
	}
	response := httptest.NewRecorder()
	m.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
	if strings.Contains(response.Body.String(), marker) || strings.Contains(response.Body.String(), runtime) || strings.Contains(response.Body.String(), installation) {
		t.Fatal("scrape exposed private payload or resource identity")
	}
	releaseOnce.Do(func() { close(release) })
	for range 17 {
		if frame := readEnvelope(t, host); frame.Type != "metrics.fixture" {
			t.Fatal("queued message lost")
		}
	}
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	metricUntil(t, func() bool {
		live.queueMu.Lock()
		defer live.queueMu.Unlock()
		return live.queuedBytes == 0 && live.inflightBytes == 0
	})
	metricUntil(t, func() bool {
		return metricValue(t, metricsSnapshot(t, m), "relay_written_frames_total", role)-before == 17
	})
	after := metricsSnapshot(t, m)
	if metricValue(t, after, "relay_written_frames_total", role)-before != 17 || metricValue(t, after, "relay_queued_bytes", role) != 0 {
		t.Fatal("writer completion was lost or queue bytes leaked")
	}
	_ = host.CloseNow()
	drain, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	if err := relay.Drain(drain); err != nil {
		t.Fatal(err)
	}
	after = metricsSnapshot(t, m)
	if metricValue(t, after, "relay_connections", map[string]string{"role": "installation", "phase": "active"}) != 0 || metricValue(t, after, "relay_draining", nil) != 1 {
		t.Fatal("closed sockets remained in current gauges")
	}
}
