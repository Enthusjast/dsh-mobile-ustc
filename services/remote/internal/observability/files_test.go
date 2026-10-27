package observability

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestFileHandoffIntervalsKeepOfferReadAndStagingDistinct(t *testing.T) {
	m := New()
	created := time.Date(2026, 10, 27, 8, 0, 0, 0, time.UTC)
	read := created.Add(4 * time.Second)
	staged := created.Add(10 * time.Second)
	m.FileHandoffMilestone("offered", time.Time{}, time.Time{}, time.Time{})
	if testutil.CollectAndCount(m.fileHandoffAge) != 0 {
		t.Fatal("offer invented a read or staging interval")
	}
	m.FileHandoffMilestone("read_started", created, time.Time{}, read)
	m.FileHandoffMilestone("staged", created, read, staged)
	for stage, expected := range map[string]float64{"read_started": 4, "staged": 10} {
		if count, sum := commandHistogramValue(t, m.fileHandoffAge.WithLabelValues(stage)); count != 1 || sum != expected {
			t.Fatal("incorrect offer age", stage, count, sum)
		}
		if got := testutil.ToFloat64(m.fileHandoffEvents.WithLabelValues(stage)); got != 1 {
			t.Fatal("lost committed milestone", stage, got)
		}
	}
	if count, sum := commandHistogramValue(t, m.fileHandoffStage); count != 1 || sum != 6 {
		t.Fatal("staging interval included time before read", count, sum)
	}
	m.FileHandoffMilestone("staged", staged.Add(time.Second), staged.Add(time.Second), staged)
	if got := testutil.ToFloat64(m.fileClock.WithLabelValues("staged")); got != 2 {
		t.Fatal("negative intervals were not reported separately", got)
	}
	if count, sum := commandHistogramValue(t, m.fileHandoffStage); count != 1 || sum != 6 {
		t.Fatal("negative interval polluted histogram", count, sum)
	}
	if got := testutil.ToFloat64(m.fileHandoffEvents.WithLabelValues("staged")); got != 2 {
		t.Fatal("clock anomaly erased a committed event", got)
	}
}
