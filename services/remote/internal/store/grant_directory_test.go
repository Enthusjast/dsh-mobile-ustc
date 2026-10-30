package store

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestGrantDirectoryCursorRejectsAmbiguousAndForeignFormats(t *testing.T) {
	cursor := grantDirectoryCursor{Version: 1, Purpose: "runtime-grants-v1", UserID: directoryOwner, ProofKeyJKT: strings.Repeat("A", 43), RuntimeID: directoryRuntime, AfterUserID: directoryTarget}
	raw, _ := json.Marshal(cursor)
	valid := base64.RawURLEncoding.EncodeToString(raw)
	if _, err := parseGrantDirectoryCursor(valid); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		`{"v":1,"v":1}`, `{} {}`, `null`,
		strings.Replace(string(raw), "runtime-grants-v1", "installation-directory-v1", 1),
		strings.Replace(string(raw), `"v":1`, `"v":1,"extra":true`, 1),
		strings.Replace(string(raw), directoryRuntime, "invalid", 1),
	} {
		if _, err := parseGrantDirectoryCursor(base64.RawURLEncoding.EncodeToString([]byte(raw))); err == nil {
			t.Fatal("invalid cursor accepted")
		}
	}
	for _, encoded := range []string{"", valid + "=", strings.Repeat("A", 1025)} {
		if _, err := parseGrantDirectoryCursor(encoded); err == nil {
			t.Fatal("noncanonical cursor accepted")
		}
	}
}
