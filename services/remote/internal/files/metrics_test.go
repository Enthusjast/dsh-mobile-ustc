package files

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"dsh-mobile-ustc/services/remote/internal/observability"
)

func assertScanMetrics(t *testing.T, metrics *observability.Metrics, direction, result string) {
	t.Helper()
	families, err := metrics.Gatherer().Gather()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, family := range families {
		if family.GetName() != "dsh_remote_file_scan_attempt_duration_seconds" {
			continue
		}
		if len(family.Metric) != 1 {
			t.Fatal("scan created extra result series")
		}
		metric := family.Metric[0]
		labels := map[string]string{}
		for _, label := range metric.Label {
			labels[label.GetName()] = label.GetValue()
		}
		if len(labels) != 2 || labels["direction"] != direction || labels["result"] != result || metric.GetHistogram().GetSampleCount() != 1 || metric.GetHistogram().GetSampleSum() <= 0 {
			t.Fatal("wrong scan result or duration", labels, metric.GetHistogram())
		}
		found = true
	}
	if !found {
		t.Fatal("claimed scan was not observed")
	}
	response := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
	for _, private := range []string{"fixture.bin", "clean file bytes", "BLOCK", "33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444"} {
		if strings.Contains(response.Body.String(), private) {
			t.Fatal("scan metric exposed file metadata or body")
		}
	}
}

func TestFileFailureClassificationNeverUsesExceptionText(t *testing.T) {
	for _, test := range []struct {
		err  error
		want string
	}{{nil, "ok"}, {context.Canceled, "cancelled"}, {context.DeadlineExceeded, "timeout"}, {ErrAccess, "access_denied"}, {ErrStale, "stale"}, {ErrConflict, "conflict"}, {ErrQuota, "quota"}, {ErrRejected, "rejected"}, {ErrIntegrity, "integrity"}, {ErrInvalid, "invalid"}, {ErrScanUnavailable, "scanner_unavailable"}, {errors.New("PRIVATE_OBJECT_KEY_AND_URL"), "unavailable"}} {
		if got := FileOperationResult(test.err); got != test.want {
			t.Fatal("wrong fixed outcome", got, test.want)
		}
	}
}
