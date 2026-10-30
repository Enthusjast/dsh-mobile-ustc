package store

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestSessionDirectoryCursorRejectsForeignPurposesAndAmbiguousJSON(t *testing.T) {
	cursor := sessionDirectoryCursor{Version: 1, Purpose: "session-directory-v1", UserID: directoryOwner, ProofKeyJKT: strings.Repeat("A", 43), RuntimeID: directoryRuntime, AfterSessionID: "99999999-9999-4999-8999-999999999999"}
	raw, _ := json.Marshal(cursor)
	valid := base64.RawURLEncoding.EncodeToString(raw)
	if _, err := parseSessionDirectoryCursor(valid); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"", valid + "=", strings.Repeat("A", 1025), base64.RawURLEncoding.EncodeToString([]byte(`{"v":1,"v":1}`)),
		base64.RawURLEncoding.EncodeToString([]byte(strings.Replace(string(raw), "session-directory-v1", "runtime-grants-v1", 1))),
		base64.RawURLEncoding.EncodeToString([]byte(strings.Replace(string(raw), `"v":1`, `"v":1,"extra":true`, 1)))} {
		if _, err := parseSessionDirectoryCursor(invalid); err == nil {
			t.Fatal("invalid session directory cursor accepted")
		}
	}
}
