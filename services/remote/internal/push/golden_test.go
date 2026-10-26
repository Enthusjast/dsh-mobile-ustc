package push

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"
)

// These samples are generated from the shared Zod schemas, independently of
// Go's field tags. Future Android adapters consume the same fixed wire values.
func TestPushSharedContractsKeepRegistrationAndReferenceWireFields(t *testing.T) {
	_, source, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "../../../../contracts/push/v1/golden"))
	for _, sample := range []struct {
		name   string
		target any
	}{{"registration", &Registration{}}, {"reference", &Reference{}}} {
		raw, err := os.ReadFile(filepath.Join(root, sample.name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if json.Unmarshal(raw, sample.target) != nil {
			t.Fatal("shared wire value rejected")
		}
		if input, ok := sample.target.(*Registration); ok && !input.Valid() {
			t.Fatal("shared endpoint intent rejected")
		}
		encoded, err := json.Marshal(sample.target)
		if err != nil {
			t.Fatal(err)
		}
		var expected, actual map[string]any
		_ = json.Unmarshal(raw, &expected)
		_ = json.Unmarshal(encoded, &actual)
		// Metadata timestamps allow RFC3339 fractional precision. Go omits a
		// zero fractional part; the provider data envelope separately emits ms.
		if value, ok := expected["expires_at"].(string); ok {
			parsed, err := time.Parse(time.RFC3339Nano, value)
			if err != nil {
				t.Fatal(err)
			}
			expected["expires_at"] = parsed.Format(time.RFC3339Nano)
		}
		if !reflect.DeepEqual(expected, actual) {
			t.Fatal("shared field names or values changed")
		}
	}
	for _, name := range []string{"registration-challenge", "interaction"} {
		raw, err := os.ReadFile(filepath.Join(root, name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var value map[string]string
		if json.Unmarshal(raw, &value) != nil || len(value) != 5 || value["v"] != "1" || !UUID(value["binding_id"]) {
			t.Fatal("provider packet shape changed")
		}
		if _, err := time.Parse(time.RFC3339Nano, value["expires_at"]); err != nil {
			t.Fatal(err)
		}
		if name == "registration-challenge" && !Secret(value["challenge"]) || name == "interaction" && !UUID(value["notification_id"]) {
			t.Fatal("provider reference purpose changed")
		}
	}
}
