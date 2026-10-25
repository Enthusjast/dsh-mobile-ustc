package files

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestFileHTTPGoldensMatchGoPublicShapesAndManifestAdmission(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("contracts source unavailable")
	}
	directory := filepath.Join(filepath.Dir(source), "../../../../contracts/files/v1/golden")
	load := func(name string) []byte {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(directory, name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	var request UploadRegistration
	if err := json.Unmarshal(load("registration"), &request); err != nil {
		t.Fatal(err)
	}
	request.RuntimeID = "66666666-6666-4666-8666-666666666666"
	request.SessionID = "22222222-2222-4222-8222-222222222222"
	if _, err := NormalizeRegistration(request); err != nil {
		t.Fatal("golden request was not admitted")
	}
	for _, name := range []string{"prepared", "clean"} {
		raw := load(name)
		var original any
		if json.Unmarshal(raw, &original) != nil {
			t.Fatal("invalid golden")
		}
		var public any
		if name == "prepared" {
			var response struct {
				OK   bool           `json:"ok"`
				Data UploadPrepared `json:"data"`
			}
			if json.Unmarshal(raw, &response) != nil {
				t.Fatal("invalid prepared shape")
			}
			public = response
		} else {
			var response struct {
				OK   bool `json:"ok"`
				Data struct {
					File Status `json:"file"`
				} `json:"data"`
			}
			if json.Unmarshal(raw, &response) != nil {
				t.Fatal("invalid status shape")
			}
			public = response
		}
		encoded, err := json.Marshal(public)
		if err != nil {
			t.Fatal(err)
		}
		var actual any
		if json.Unmarshal(encoded, &actual) != nil || !reflect.DeepEqual(original, actual) {
			t.Fatalf("Go public shape drifted from %s", name)
		}
	}
}
