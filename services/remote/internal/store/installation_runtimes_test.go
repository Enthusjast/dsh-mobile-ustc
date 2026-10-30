package store

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestInstallationRuntimeCursorRejectsForeignPurposesAndAmbiguousJSON(t *testing.T) {
	cursor := installationRuntimeCursor{Version: 1, Purpose: "installation-runtimes-v1", UserID: directoryOwner, ProofKeyJKT: strings.Repeat("A", 43), InstallationID: managedInstallation, AfterRuntimeID: directoryRuntime}
	raw, _ := json.Marshal(cursor)
	valid := base64.RawURLEncoding.EncodeToString(raw)
	if _, err := parseInstallationRuntimeCursor(valid); err != nil {
		t.Fatal(err)
	}
	for _, encoded := range []string{"", valid + "=", strings.Repeat("A", 1025), base64.RawURLEncoding.EncodeToString([]byte(`{"v":1,"v":1}`)),
		base64.RawURLEncoding.EncodeToString([]byte(strings.Replace(string(raw), "installation-runtimes-v1", "installation-directory-v1", 1))),
		base64.RawURLEncoding.EncodeToString([]byte(strings.Replace(string(raw), `"v":1`, `"v":1,"extra":true`, 1)))} {
		if _, err := parseInstallationRuntimeCursor(encoded); err == nil {
			t.Fatal("invalid profile directory cursor accepted")
		}
	}
}
