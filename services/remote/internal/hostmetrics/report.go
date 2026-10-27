// Package hostmetrics defines bounded, connection-scoped, self-reported native
// observations. It carries no command/resource identity and grants no authority.
package hostmetrics

import (
	"errors"
	"reflect"
)

const Capability = "host.observations.v1"
const MaxCount uint64 = 1_000_000_000
const MaxSum uint64 = 9_007_199_254_740_991

var BucketMicros = []uint64{1000, 5000, 10000, 50000, 100000, 300000, 500000, 1000000, 5000000, 10000000, 30000000, 60000000}
var ErrReport = errors.New("host observations: invalid or nonmonotone report")

type Series struct {
	Operation string   `json:"operation"`
	Result    string   `json:"result"`
	Count     uint64   `json:"count"`
	SumMicros *uint64  `json:"sum_micros"`
	Buckets   []uint64 `json:"buckets"`
}
type Report struct {
	ConnectionID string   `json:"connection_id"`
	Sequence     uint64   `json:"sequence"`
	Dropped      *uint64  `json:"dropped"`
	Series       []Series `json:"series"`
}
type DeltaSeries struct {
	Operation, Result string
	Count, SumMicros  uint64
	Buckets           []uint64
}
type Delta struct {
	Series    []DeltaSeries
	Dropped   uint64
	Duplicate bool
}

func Pair(operation, result string) bool {
	switch operation {
	case "checkpoint", "cold_checkpoint":
		return result == "persisted" || result == "failed" || result == "unavailable"
	case "prompt", "create", "prompt_reconcile":
		return result == "ok" || result == "error" || result == "cancelled"
	default:
		return false
	}
}
func key(series Series) string { return series.Operation + ":" + series.Result }

func (report Report) valid() bool {
	if report.Sequence < 1 || report.Sequence > MaxCount || report.Dropped == nil || *report.Dropped > MaxCount || report.Series == nil || len(report.Series) > 15 {
		return false
	}
	seen := map[string]bool{}
	for _, series := range report.Series {
		if !Pair(series.Operation, series.Result) || seen[key(series)] || series.Count < 1 || series.Count > MaxCount || series.SumMicros == nil || *series.SumMicros > MaxSum || len(series.Buckets) != len(BucketMicros) {
			return false
		}
		seen[key(series)] = true
		if !validHistogram(series.Count, *series.SumMicros, series.Buckets) {
			return false
		}
	}
	return true
}

func validHistogram(count, sum uint64, buckets []uint64) bool {
	var previous, lower, upper uint64
	for i, value := range buckets {
		if value < previous || value > count {
			return false
		}
		observations := value - previous
		if i > 0 {
			lower += observations * (BucketMicros[i-1] + 1)
		}
		upper += observations * BucketMicros[i]
		previous = value
	}
	outside := count - previous
	lower += outside * (BucketMicros[len(BucketMicros)-1] + 1)
	return sum >= lower && (outside > 0 || sum <= upper)
}

// A repeated sequence is accepted only if identical. Every previous cell must
// remain present; counters, sum, and cumulative bucket deltas cannot regress.
func Difference(previous *Report, current Report) (Delta, error) {
	if !current.valid() {
		return Delta{}, ErrReport
	}
	old := map[string]Series{}
	if previous != nil {
		if !previous.valid() {
			return Delta{}, ErrReport
		}
		if current.ConnectionID != previous.ConnectionID || current.Sequence < previous.Sequence || *current.Dropped < *previous.Dropped {
			return Delta{}, ErrReport
		}
		if current.Sequence == previous.Sequence {
			if reflect.DeepEqual(*previous, current) {
				return Delta{Duplicate: true}, nil
			}
			return Delta{}, ErrReport
		}
		for _, series := range previous.Series {
			old[key(series)] = series
		}
	}
	delta := Delta{Dropped: *current.Dropped}
	if previous != nil {
		delta.Dropped -= *previous.Dropped
	}
	for _, series := range current.Series {
		item := DeltaSeries{Operation: series.Operation, Result: series.Result, Count: series.Count, SumMicros: *series.SumMicros, Buckets: append([]uint64(nil), series.Buckets...)}
		if earlier, ok := old[key(series)]; ok {
			if series.Count < earlier.Count || *series.SumMicros < *earlier.SumMicros {
				return Delta{}, ErrReport
			}
			item.Count -= earlier.Count
			item.SumMicros -= *earlier.SumMicros
			for i, value := range item.Buckets {
				if value < earlier.Buckets[i] {
					return Delta{}, ErrReport
				}
				item.Buckets[i] -= earlier.Buckets[i]
			}
			delete(old, key(series))
		}
		if !validHistogram(item.Count, item.SumMicros, item.Buckets) {
			return Delta{}, ErrReport
		}
		if item.Count > 0 {
			delta.Series = append(delta.Series, item)
		}
	}
	if len(old) != 0 {
		return Delta{}, ErrReport
	}
	return delta, nil
}
