package observability

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type unknownSourceFunc func(context.Context) (UnknownResultCounts, error)

func (source unknownSourceFunc) UnknownResults(ctx context.Context) (UnknownResultCounts, error) {
	return source(ctx)
}

func unknownGauges(t *testing.T, metrics *Metrics) map[string]float64 {
	t.Helper()
	families, err := metrics.Gatherer().Gather()
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]float64{}
	for _, family := range families {
		if !strings.HasPrefix(family.GetName(), "dsh_remote_unknown_") {
			continue
		}
		for _, metric := range family.Metric {
			if metric.Gauge == nil {
				continue
			}
			key := strings.TrimPrefix(family.GetName(), "dsh_remote_")
			if len(metric.Label) == 1 {
				key += ":" + metric.Label[0].GetValue()
			}
			values[key] = metric.GetGauge().GetValue()
		}
	}
	return values
}

func TestUnknownSnapshotsRetainLastCountsOnFailureWithoutInventingZero(t *testing.T) {
	m := New()
	initial := unknownGauges(t, m)
	if _, exists := initial["unknown_results:command"]; exists || initial["unknown_snapshot_available"] != 0 || initial["unknown_snapshot_last_success_timestamp_seconds"] != 0 {
		t.Fatal("unsampled database was presented as known empty", initial)
	}
	m.refreshUnknownResults(t.Context(), unknownSourceFunc(func(context.Context) (UnknownResultCounts, error) {
		return UnknownResultCounts{Commands: 7, Approvals: 3}, nil
	}))
	first := unknownGauges(t, m)
	if first["unknown_results:command"] != 7 || first["unknown_results:approval"] != 3 || first["unknown_snapshot_available"] != 1 || first["unknown_snapshot_last_success_timestamp_seconds"] <= 0 {
		t.Fatal("snapshot lost its counts or freshness", first)
	}
	m.refreshUnknownResults(t.Context(), unknownSourceFunc(func(context.Context) (UnknownResultCounts, error) {
		return UnknownResultCounts{}, errors.New("PRIVATE_DATABASE_ERROR_AND_DSN")
	}))
	failed := unknownGauges(t, m)
	if failed["unknown_results:command"] != 7 || failed["unknown_results:approval"] != 3 || failed["unknown_snapshot_available"] != 0 || failed["unknown_snapshot_last_success_timestamp_seconds"] != first["unknown_snapshot_last_success_timestamp_seconds"] {
		t.Fatal("query failure reset counts or advanced freshness", failed)
	}
	m.refreshUnknownResults(t.Context(), unknownSourceFunc(func(context.Context) (UnknownResultCounts, error) { return UnknownResultCounts{Commands: -1}, nil }))
	invalid := unknownGauges(t, m)
	if invalid["unknown_results:command"] != 7 || invalid["unknown_snapshot_available"] != 0 {
		t.Fatal("invalid negative count replaced snapshot", invalid)
	}
	m.refreshUnknownResults(t.Context(), unknownSourceFunc(func(context.Context) (UnknownResultCounts, error) { return UnknownResultCounts{}, nil }))
	cleared := unknownGauges(t, m)
	if cleared["unknown_results:command"] != 0 || cleared["unknown_results:approval"] != 0 || cleared["unknown_snapshot_available"] != 1 {
		t.Fatal("successful zero snapshot remained stale", cleared)
	}
	response := httptest.NewRecorder()
	m.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
	if strings.Contains(response.Body.String(), "PRIVATE_DATABASE_ERROR_AND_DSN") {
		t.Fatal("sampler leaked database error text")
	}
}

func TestUnknownSamplerDisabledAndScrapesDoNoSourceIOAndShutdownCancelsRead(t *testing.T) {
	var calls atomic.Int32
	started := make(chan struct{})
	source := unknownSourceFunc(func(ctx context.Context) (UnknownResultCounts, error) {
		calls.Add(1)
		close(started)
		<-ctx.Done()
		return UnknownResultCounts{}, ctx.Err()
	})
	RunUnknownResults(t.Context(), nil, source)
	if calls.Load() != 0 {
		t.Fatal("disabled metrics accessed database")
	}
	m := New()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); RunUnknownResults(ctx, m, source) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("sampler did not start")
	}
	for range 3 {
		_ = unknownGauges(t, m)
	}
	if calls.Load() != 1 {
		t.Fatal("scraping performed source I/O or overlapped sampling")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not cancel the in-flight query")
	}
	if values := unknownGauges(t, m); values["unknown_snapshot_available"] != 0 || values["unknown_snapshot_last_success_timestamp_seconds"] != 0 {
		t.Fatal("cancelled read created successful snapshot", values)
	}
}
