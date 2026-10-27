package observability

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestPushAgesUseCreationAndKeepClientReportsSeparate(t *testing.T) {
	m := New()
	created := time.Date(2026, 10, 27, 8, 0, 0, 0, time.UTC)
	m.PushSend("approval", "provider_accepted", time.Second)
	if testutil.CollectAndCount(m.pushDeliveries) != 0 || testutil.CollectAndCount(m.pushReceipts) != 0 {
		t.Fatal("sender result invented committed completion or display report")
	}
	m.PushDelivery("approval", "provider_accepted", "", created, created.Add(10*time.Second))
	if count, sum := commandHistogramValue(t, m.pushDeliveryAge.WithLabelValues("approval", "provider_accepted")); count != 1 || sum != 10 {
		t.Fatal("delivery age is not creation-to-update", count, sum)
	}
	if testutil.CollectAndCount(m.pushReceipts) != 0 {
		t.Fatal("provider acceptance invented phone display report")
	}
	m.PushReceipt("approval", "posted", created, created.Add(30*time.Second))
	if count, sum := commandHistogramValue(t, m.pushReceiptAge.WithLabelValues("approval", "posted")); count != 1 || sum != 30 {
		t.Fatal("receipt age was confused with provider-to-display latency", count, sum)
	}
	m.PushReceipt("approval", "posted", created, created.Add(-time.Second))
	if count, sum := commandHistogramValue(t, m.pushReceiptAge.WithLabelValues("approval", "posted")); count != 1 || sum != 30 {
		t.Fatal("negative database interval entered histogram", count, sum)
	}
	if testutil.ToFloat64(m.pushClock.WithLabelValues("receipt")) != 1 || testutil.ToFloat64(m.pushReceipts.WithLabelValues("approval", "posted")) != 2 {
		t.Fatal("clock anomaly lost report or warning")
	}
}
