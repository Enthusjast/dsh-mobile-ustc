package observability

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
)

func TestUnknownIdentityAndTextCannotCreateMetricLabels(t *testing.T) {
	m := New()
	const secret = "PRIVATE_SUBJECT_BODY_TOKEN_MARKER"
	for i := range 1000 {
		untrusted := fmt.Sprintf("%s-%d", secret, i)
		m.Received(untrusted, 7)
		m.Written(untrusted, 7, time.Millisecond, errors.New(untrusted))
		m.Dequeued(untrusted, time.Millisecond)
		m.RejectedSend(untrusted, untrusted)
		m.ProtocolError("protocol." + untrusted)
		m.Forward(untrusted, time.Millisecond)
		m.Revoked(untrusted, untrusted)
		m.ControlRun(untrusted, untrusted, time.Millisecond)
		m.ControlEvent(untrusted, untrusted, time.Now())
		m.CommandTransition(untrusted, untrusted, untrusted, untrusted, time.Now().Add(-time.Second), time.Now().Add(-time.Second), time.Now())
		m.CommandStore(untrusted, untrusted, time.Millisecond)
	}
	if got := testutil.CollectAndCount(m.rejectedSends); got != 1 {
		t.Fatalf("untrusted inputs created %d rejection series", got)
	}
	if got := testutil.CollectAndCount(m.controlEvents); got != 1 {
		t.Fatalf("untrusted inputs created %d event series", got)
	}
	if got := testutil.CollectAndCount(m.commandTransitions); got != 1 {
		t.Fatalf("untrusted command fields created %d series", got)
	}
	if got := testutil.CollectAndCount(m.commandStore); got != 1 {
		t.Fatalf("untrusted command outcomes created %d series", got)
	}
	response := httptest.NewRecorder()
	m.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
	if response.Code != 200 || !strings.Contains(response.Body.String(), "dsh_remote_relay_received_frames_total{role=\"other\"} 1000") || strings.Contains(response.Body.String(), secret) {
		t.Fatal("scrape failed, lost observations, or exposed untrusted metadata")
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("metrics response can be cached")
	}
}

func TestControlAgeTracksOnlyPublishedEventsAndReportsClockSkew(t *testing.T) {
	m := New()
	past := time.Now().Add(-time.Second)
	m.ControlEvent("device.revoked", "apply_error", past)
	m.ControlEvent("device.revoked", "ack_error", past)
	if testutil.CollectAndCount(m.controlAge) != 0 {
		t.Fatal("failed publication was counted as completed propagation")
	}
	m.ControlEvent("device.revoked", "published", past)
	m.ControlEvent("device.revoked", "published", time.Now().Add(time.Hour))
	metric := &dto.Metric{}
	if err := m.controlAge.WithLabelValues("device.revoked").(prometheus.Metric).Write(metric); err != nil {
		t.Fatal(err)
	}
	if metric.GetHistogram().GetSampleCount() != 1 || metric.GetHistogram().GetSampleSum() < 1 || testutil.ToFloat64(m.clockSkew) != 1 {
		t.Fatal("future timestamp polluted completed age observations")
	}
	m.ControlRun("leases", "ok", time.Millisecond)
	last := testutil.ToFloat64(m.controlSuccess.WithLabelValues("leases"))
	if last <= 0 || testutil.ToFloat64(m.controlReady.WithLabelValues("leases")) != 1 {
		t.Fatal("worker success was not observed")
	}
	m.ControlRun("leases", "error", time.Millisecond)
	m.ControlRun("leases", "cancelled", time.Millisecond)
	if testutil.ToFloat64(m.controlReady.WithLabelValues("leases")) != 0 || testutil.ToFloat64(m.controlSuccess.WithLabelValues("leases")) != last {
		t.Fatal("error or cancellation restored availability or advanced last success")
	}
}

type blockedCollector struct {
	release <-chan struct{}
	started chan struct{}
	calls   atomic.Int64
	active  atomic.Int64
	maximum atomic.Int64
	desc    *prometheus.Desc
}

func (collector *blockedCollector) Describe(out chan<- *prometheus.Desc) { out <- collector.desc }
func (collector *blockedCollector) Collect(out chan<- prometheus.Metric) {
	active := collector.active.Add(1)
	defer collector.active.Add(-1)
	for previous := collector.maximum.Load(); active > previous; previous = collector.maximum.Load() {
		if collector.maximum.CompareAndSwap(previous, active) {
			break
		}
	}
	if collector.calls.Add(1) == 1 {
		close(collector.started)
	}
	<-collector.release
	out <- prometheus.MustNewConstMetric(collector.desc, prometheus.GaugeValue, 1)
}

func TestConcurrentScrapesShareOneGatherAndExcessRequestsAreBounded(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	collector := &blockedCollector{release: release, started: make(chan struct{}), desc: prometheus.NewDesc("fixture_blocked_collection", "Controlled collector fixture.", nil, nil)}
	m := New()
	m.Register(collector)
	server := httptest.NewServer(m.Handler())
	t.Cleanup(server.Close)
	client := &http.Client{Timeout: 5 * time.Second}
	t.Cleanup(client.CloseIdleConnections)
	type result struct {
		code int
		err  error
	}
	results := make(chan result, 3)
	request := func() {
		response, err := client.Get(server.URL + "/metrics")
		if err != nil {
			results <- result{err: err}
			return
		}
		_, readErr := io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		results <- result{code: response.StatusCode, err: readErr}
	}
	go request()
	select {
	case <-collector.started:
	case <-time.After(3 * time.Second):
		t.Fatal("collector never started")
	}
	go request()
	go request()
	select {
	case rejected := <-results:
		if rejected.err != nil || rejected.code != 503 {
			t.Fatal("excess scrape was not rejected", rejected)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("excess scrape was not bounded")
	}
	if collector.calls.Load() != 1 {
		t.Fatal("concurrent scrapes duplicated blocked collection")
	}
	once.Do(func() { close(release) })
	for range 2 {
		select {
		case completed := <-results:
			if completed.err != nil || completed.code != 200 {
				t.Fatal("admitted scrape did not finish", completed)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("admitted scrape did not finish")
		}
	}
	// A request may reach Gather after the first cycle finishes; a fresh
	// sequential cycle is valid. Only overlapping collection is forbidden.
	if collector.maximum.Load() != 1 {
		t.Fatal("admitted scrapes overlapped their underlying collection")
	}
}
