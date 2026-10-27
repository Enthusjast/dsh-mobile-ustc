package observability

import (
	"dsh-mobile-ustc/services/remote/internal/hostmetrics"
	"github.com/prometheus/client_golang/prometheus"
	"sync"
)

var nativeDurationDesc = prometheus.NewDesc("dsh_remote_host_native_operation_duration_seconds", "Self-reported Host operation durations from the current authenticated connection; not relay latency, authority or command acceptance.", []string{"operation", "result"}, nil)
var nativeCountDesc = prometheus.NewDesc("dsh_remote_host_native_operations_total", "Self-reported Host operations aggregated from validated connection counter deltas.", []string{"operation", "result"}, nil)
var nativeDroppedDesc = prometheus.NewDesc("dsh_remote_host_native_dropped_samples_total", "Host-reported samples discarded by the bounded observation window.", nil, nil)

type nativeTotal struct {
	operation, result string
	count             uint64
	sum               float64
	buckets           map[float64]uint64
}
type nativeCollector struct {
	mu      sync.Mutex
	totals  map[string]*nativeTotal
	dropped uint64
}

func newNativeCollector() *nativeCollector {
	return &nativeCollector{totals: map[string]*nativeTotal{}}
}
func (collector *nativeCollector) add(delta hostmetrics.Delta) {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	collector.dropped += delta.Dropped
	for _, series := range delta.Series {
		if !hostmetrics.Pair(series.Operation, series.Result) || len(series.Buckets) != len(hostmetrics.BucketMicros) {
			continue
		}
		key := series.Operation + ":" + series.Result
		total := collector.totals[key]
		if total == nil {
			total = &nativeTotal{operation: series.Operation, result: series.Result, buckets: map[float64]uint64{}}
			collector.totals[key] = total
		}
		total.count += series.Count
		total.sum += float64(series.SumMicros) / 1e6
		for i, bound := range hostmetrics.BucketMicros {
			total.buckets[float64(bound)/1e6] += series.Buckets[i]
		}
	}
}
func (collector *nativeCollector) Describe(out chan<- *prometheus.Desc) {
	out <- nativeDurationDesc
	out <- nativeCountDesc
	out <- nativeDroppedDesc
}
func (collector *nativeCollector) Collect(out chan<- prometheus.Metric) {
	collector.mu.Lock()
	values := make([]nativeTotal, 0, len(collector.totals))
	dropped := collector.dropped
	for _, item := range collector.totals {
		copy := *item
		copy.buckets = map[float64]uint64{}
		for bound, count := range item.buckets {
			copy.buckets[bound] = count
		}
		values = append(values, copy)
	}
	collector.mu.Unlock()
	for _, item := range values {
		out <- prometheus.MustNewConstHistogram(nativeDurationDesc, item.count, item.sum, item.buckets, item.operation, item.result)
		out <- prometheus.MustNewConstMetric(nativeCountDesc, prometheus.CounterValue, float64(item.count), item.operation, item.result)
	}
	out <- prometheus.MustNewConstMetric(nativeDroppedDesc, prometheus.CounterValue, float64(dropped))
}

func (m *Metrics) HostObservations(delta hostmetrics.Delta) {
	if m != nil {
		m.native.add(delta)
	}
}
func (m *Metrics) HostObservationReport(result string) {
	if m != nil {
		m.nativeReports.WithLabelValues(fixed(result, "accepted", "duplicate", "rejected", "throttled", "denied")).Inc()
	}
}
