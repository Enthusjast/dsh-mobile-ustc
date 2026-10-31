package observability

import (
	"encoding/json"
	"os"
	"testing"

	"dsh-mobile-ustc/services/remote/internal/hostmetrics"
)

func TestNativeHistogramAddsOnlyValidatedDeltasAndUsesSeconds(t *testing.T) {
	read := func(name string) hostmetrics.Report {
		t.Helper()
		raw, err := os.ReadFile("../../../../contracts/ws/v1/golden/" + name + ".json")
		if err != nil {
			t.Fatal(err)
		}
		var frame struct {
			Payload hostmetrics.Report `json:"payload"`
		}
		if json.Unmarshal(raw, &frame) != nil {
			t.Fatal("golden")
		}
		return frame.Payload
	}
	first, next := read("host-observations"), read("host-observations-next")
	metrics := New()
	initial, err := hostmetrics.Difference(nil, first)
	if err != nil {
		t.Fatal(err)
	}
	metrics.HostObservations(initial)
	delta, err := hostmetrics.Difference(&first, next)
	if err != nil {
		t.Fatal(err)
	}
	metrics.HostObservations(delta)
	// A separate connection reports new operations from its own zero baseline.
	metrics.HostObservations(initial)
	families, err := metrics.Gatherer().Gather()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, family := range families {
		if family.GetName() != "dsh_remote_host_native_operation_duration_seconds" {
			continue
		}
		for _, metric := range family.Metric {
			labels := map[string]string{}
			for _, label := range metric.Label {
				labels[label.GetName()] = label.GetValue()
			}
			if labels["operation"] != "checkpoint" || labels["result"] != "persisted" {
				continue
			}
			found = true
			hist := metric.GetHistogram()
			if hist.GetSampleCount() != 2 || hist.GetSampleSum() != .003 {
				t.Fatal("native counts or microsecond conversion wrong", hist)
			}
			for _, bucket := range hist.Bucket {
				if bucket.GetUpperBound() == .001 && bucket.GetCumulativeCount() != 0 || bucket.GetUpperBound() == .005 && bucket.GetCumulativeCount() != 2 {
					t.Fatal("native histogram boundaries changed", hist)
				}
			}
		}
	}
	if !found {
		t.Fatal("native histogram absent")
	}
}

func TestJournalHistogramUsesFixedOperationsAndSeconds(t *testing.T) {
	raw, err := os.ReadFile("../../../../contracts/ws/v1/golden/host-observations-journal.json")
	if err != nil {
		t.Fatal(err)
	}
	var frame struct {
		Payload hostmetrics.Report `json:"payload"`
	}
	if err := json.Unmarshal(raw, &frame); err != nil {
		t.Fatal(err)
	}
	delta, err := hostmetrics.Difference(nil, frame.Payload)
	if err != nil {
		t.Fatal(err)
	}
	metrics := New()
	metrics.HostObservations(delta)
	families, err := metrics.Gatherer().Gather()
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, family := range families {
		if family.GetName() != "dsh_remote_host_native_operation_duration_seconds" {
			continue
		}
		for _, metric := range family.Metric {
			labels := map[string]string{}
			for _, label := range metric.Label {
				labels[label.GetName()] = label.GetValue()
			}
			want := .007
			switch labels["operation"] {
			case "journal_command":
				if labels["result"] != "persisted" {
					t.Fatal("command result label")
				}
			case "journal_approval":
				want = .012
				if labels["result"] != "failed" {
					t.Fatal("approval result label")
				}
			default:
				continue
			}
			hist := metric.GetHistogram()
			if hist.GetSampleCount() != 1 || hist.GetSampleSum() != want {
				t.Fatal("journal histogram units", hist)
			}
			if len(metric.Label) != 2 {
				t.Fatal("unexpected dynamic journal labels")
			}
			found++
		}
	}
	if found != 2 {
		t.Fatal("journal histograms absent", found)
	}
}
