package store

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestResourceDirectoryCursorsRejectOtherPurposesAndAmbiguousJSON(t *testing.T) {
	cursor := resourceDirectoryCursor{Version: 1, Purpose: "runtime-directory-v1", UserID: directoryOwner, ProofKeyJKT: strings.Repeat("A", 43), AfterID: directoryRuntime}
	raw, _ := json.Marshal(cursor)
	valid := base64.RawURLEncoding.EncodeToString(raw)
	if _, err := parseResourceDirectoryCursor(valid, "runtime-directory-v1"); err != nil {
		t.Fatal(err)
	}
	if _, err := parseResourceDirectoryCursor(valid, "host-directory-v1"); err == nil {
		t.Fatal("runtime cursor accepted by host directory")
	}
	for _, encoded := range []string{"", valid + "=", strings.Repeat("A", 1025), base64.RawURLEncoding.EncodeToString([]byte(`{"v":1,"v":1}`)),
		base64.RawURLEncoding.EncodeToString([]byte(strings.Replace(string(raw), `"v":1`, `"v":1,"extra":true`, 1)))} {
		if _, err := parseResourceDirectoryCursor(encoded, "runtime-directory-v1"); err == nil {
			t.Fatal("ambiguous directory cursor accepted")
		}
	}
}
