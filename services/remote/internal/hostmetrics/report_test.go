package hostmetrics

import (
	"encoding/json"
	"os"
	"testing"
)

func golden(t *testing.T, name string) Report {
	t.Helper()
	raw, err := os.ReadFile("../../../../contracts/ws/v1/golden/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var frame struct {
		Payload Report `json:"payload"`
	}
	if json.Unmarshal(raw, &frame) != nil {
		t.Fatal("invalid Host observation golden")
	}
	return frame.Payload
}
func clone(t *testing.T, report Report) Report {
	t.Helper()
	raw, _ := json.Marshal(report)
	var value Report
	if json.Unmarshal(raw, &value) != nil {
		t.Fatal("clone")
	}
	return value
}

func TestNativeCounterDeltasMatchTypeScriptGoldensAndRejectRewrites(t *testing.T) {
	first, next := golden(t, "host-observations"), golden(t, "host-observations-next")
	initial, err := Difference(nil, first)
	if err != nil || len(initial.Series) != 1 || initial.Series[0].Count != 1 || initial.Series[0].SumMicros != 1500 {
		t.Fatal("initial histogram", initial, err)
	}
	delta, err := Difference(&first, next)
	if err != nil || len(delta.Series) != 2 {
		t.Fatal("counter delta", delta, err)
	}
	if duplicate, err := Difference(&next, clone(t, next)); err != nil || !duplicate.Duplicate {
		t.Fatal("duplicate was not idempotent", err)
	}
	for _, change := range []func(*Report){
		func(r *Report) { r.Sequence = first.Sequence },
		func(r *Report) { r.ConnectionID = "wrong connection" },
		func(r *Report) { r.Series = r.Series[:1] },
		func(r *Report) { r.Series = append(r.Series, r.Series[0]) },
		func(r *Report) { r.Dropped = nil },
		func(r *Report) { r.Series[0].SumMicros = nil },
		func(r *Report) { r.Series[0].Operation = "PRIVATE_PATH" },
		func(r *Report) { r.Series[0].Count = MaxCount + 1 },
		func(r *Report) { r.Series[0].Buckets[0] = MaxCount },
		func(r *Report) { value := uint64(0); r.Series[0].SumMicros = &value },
	} {
		candidate := clone(t, next)
		change(&candidate)
		if _, err := Difference(&first, candidate); err == nil {
			t.Fatal("invalid report accepted")
		}
	}
}
