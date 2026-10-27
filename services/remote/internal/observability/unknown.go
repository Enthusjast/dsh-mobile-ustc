package observability

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type UnknownResultCounts struct {
	Commands, Approvals int64
}

type UnknownResultSource interface {
	UnknownResults(context.Context) (UnknownResultCounts, error)
}

type unknownSnapshot struct {
	counts    UnknownResultCounts
	updated   time.Time
	available bool
}

// One cached pair is copied under a lock so a scrape cannot mix two snapshots.
// A failure retains the last successful counts and timestamp, with availability 0.
type unknownCollector struct {
	mu                                  sync.Mutex
	snapshot                            unknownSnapshot
	counts, available, lastSuccess, age *prometheus.Desc
}

func newUnknownCollector() *unknownCollector {
	return &unknownCollector{
		counts:      prometheus.NewDesc("dsh_remote_unknown_results", "Current database rows in outcome_unknown at the last successful snapshot; includes retained recovery/history rows, not transition entries.", []string{"kind"}, nil),
		available:   prometheus.NewDesc("dsh_remote_unknown_snapshot_available", "One if the most recent background snapshot attempt succeeded; check age separately.", nil, nil),
		lastSuccess: prometheus.NewDesc("dsh_remote_unknown_snapshot_last_success_timestamp_seconds", "Process wall-clock time at last successful background snapshot, zero before any success.", nil, nil),
		age:         prometheus.NewDesc("dsh_remote_unknown_snapshot_age_seconds", "Monotonic age of the cached successful snapshot; absent before first success.", nil, nil),
	}
}

func (collector *unknownCollector) Describe(out chan<- *prometheus.Desc) {
	for _, desc := range []*prometheus.Desc{collector.counts, collector.available, collector.lastSuccess, collector.age} {
		out <- desc
	}
}

func (collector *unknownCollector) Collect(out chan<- prometheus.Metric) {
	collector.mu.Lock()
	snapshot := collector.snapshot
	collector.mu.Unlock()
	available, updated := float64(0), float64(0)
	if snapshot.available {
		available = 1
	}
	if !snapshot.updated.IsZero() {
		updated = float64(snapshot.updated.UnixNano()) / 1e9
		out <- prometheus.MustNewConstMetric(collector.counts, prometheus.GaugeValue, float64(snapshot.counts.Commands), "command")
		out <- prometheus.MustNewConstMetric(collector.counts, prometheus.GaugeValue, float64(snapshot.counts.Approvals), "approval")
		out <- prometheus.MustNewConstMetric(collector.age, prometheus.GaugeValue, max(0, time.Since(snapshot.updated).Seconds()))
	}
	out <- prometheus.MustNewConstMetric(collector.available, prometheus.GaugeValue, available)
	out <- prometheus.MustNewConstMetric(collector.lastSuccess, prometheus.GaugeValue, updated)
}

// RunUnknownResults performs at most one query at a time, with a one-second
// deadline and a ten-second pause after each attempt. Disabled metrics do no I/O.
func RunUnknownResults(ctx context.Context, metrics *Metrics, source UnknownResultSource) {
	if metrics == nil {
		return
	}
	for ctx.Err() == nil {
		attempt, cancel := context.WithTimeout(ctx, time.Second)
		metrics.refreshUnknownResults(attempt, source)
		cancel()
		timer := time.NewTimer(10 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (metrics *Metrics) refreshUnknownResults(ctx context.Context, source UnknownResultSource) {
	started := time.Now()
	counts, err := source.UnknownResults(ctx)
	result := "ok"
	if err != nil {
		switch {
		case errors.Is(ctx.Err(), context.Canceled):
			result = "cancelled"
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			result = "timeout"
		default:
			result = "error"
		}
	} else if counts.Commands < 0 || counts.Approvals < 0 {
		result = "invalid"
	}
	metrics.unknown.mu.Lock()
	metrics.unknown.snapshot.available = result == "ok"
	if result == "ok" {
		metrics.unknown.snapshot.counts = counts
		metrics.unknown.snapshot.updated = time.Now()
	}
	metrics.unknown.mu.Unlock()
	metrics.unknownSnapshots.WithLabelValues(result).Observe(time.Since(started).Seconds())
}
