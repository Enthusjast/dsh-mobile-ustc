package observability

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"testing"
	"time"
)

func commandHistogramValue(t *testing.T, value prometheus.Observer) (uint64, float64) {
	t.Helper()
	metric := &dto.Metric{}
	if err := value.(prometheus.Metric).Write(metric); err != nil {
		t.Fatal(err)
	}
	return metric.GetHistogram().GetSampleCount(), metric.GetHistogram().GetSampleSum()
}

func TestCommandAgesUseDatabaseIntervalsAndKeepEntrySeparateFromDwell(t *testing.T) {
	m := New()
	created := time.Date(2026, 10, 27, 8, 0, 0, 0, time.UTC)
	previous := created.Add(10 * time.Second)
	entered := created.Add(12 * time.Second)
	m.CommandTransition("message.submit", "none", "received", "device", created, time.Time{}, created)
	if testutil.CollectAndCount(m.commandAge) != 0 || testutil.CollectAndCount(m.commandDwell) != 0 {
		t.Fatal("creation invented a completed stage interval")
	}
	m.CommandTransition("message.submit", "host_accepted", "agent_queued", "host", created, previous, entered)
	if count, sum := commandHistogramValue(t, m.commandAge.WithLabelValues("message.submit", "agent_queued")); count != 1 || sum != 12 {
		t.Fatal("age is not command creation to state entry", count, sum)
	}
	if count, sum := commandHistogramValue(t, m.commandDwell.WithLabelValues("message.submit", "host_accepted", "agent_queued")); count != 1 || sum != 2 {
		t.Fatal("dwell is not previous state entry to current entry", count, sum)
	}
	m.CommandTransition("message.submit", "agent_queued", "observed", "host", created, entered.Add(time.Second), entered)
	if testutil.ToFloat64(m.commandClock.WithLabelValues("dwell")) != 1 {
		t.Fatal("backward state timestamp was not reported")
	}
	if count, sum := commandHistogramValue(t, m.commandAge.WithLabelValues("message.submit", "observed")); count != 1 || sum != 12 {
		t.Fatal("valid age was dropped with invalid dwell")
	}
	if testutil.ToFloat64(m.commandTransitions.WithLabelValues("message.submit", "agent_queued", "observed", "host")) != 1 {
		t.Fatal("timestamp anomaly erased committed state observation")
	}
}
