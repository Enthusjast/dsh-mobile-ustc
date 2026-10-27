package httpapi_test

import (
	"testing"
	"time"
)

func TestCapacityQuantilesKeepSparseTailAndIgnoreUnattemptedAdmissions(t *testing.T) {
	values := []time.Duration{0, time.Millisecond, 2 * time.Millisecond, 3 * time.Millisecond, 4 * time.Millisecond, time.Second}
	got := capacityQuantiles(values)
	if got["p95"] != 1000 || got["p99"] != 1000 || got["max"] != 1000 || got["p50"] != 3 {
		t.Fatal("sparse workload tail could incorrectly pass its 500ms budget", got)
	}
	if len(capacityQuantiles([]time.Duration{0, 0})) != 0 {
		t.Fatal("unattempted admissions created artificial fast samples")
	}
}
