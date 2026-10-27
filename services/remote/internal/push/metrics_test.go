package push

import (
	"net/http/httptest"
	"strings"
	"testing"

	"dsh-mobile-ustc/services/remote/internal/observability"
)

func assertSenderSamples(t *testing.T, metrics *observability.Metrics, kind, result string, expected uint64) {
	t.Helper()
	families, err := metrics.Gatherer().Gather()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, family := range families {
		if family.GetName() == "dsh_remote_push_delivery_results_total" || family.GetName() == "dsh_remote_push_client_receipts_total" {
			t.Fatal("sender result invented database or client outcome")
		}
		if family.GetName() != "dsh_remote_push_provider_send_duration_seconds" {
			continue
		}
		for _, metric := range family.Metric {
			labels := map[string]string{}
			for _, label := range metric.Label {
				labels[label.GetName()] = label.GetValue()
			}
			if labels["kind"] == kind && labels["result"] == result {
				if len(labels) != 2 || metric.GetHistogram().GetSampleCount() != expected || metric.GetHistogram().GetSampleSum() <= 0 {
					t.Fatal("sender samples or duration differ", labels, metric.GetHistogram())
				}
				found = true
			}
		}
	}
	if !found {
		t.Fatal("sender attempt not observed", kind, result)
	}
	response := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
	for _, private := range []string{"PRIVATE_ACCESS_TOKEN", "PRIVATE_PROVIDER_SECRET", "fixture-project", "opaque-result", "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", "c" + strings.Repeat("A", 21)} {
		if strings.Contains(response.Body.String(), private) {
			t.Fatal("sender metrics exposed credentials, identities, endpoint or response text")
		}
	}
}
