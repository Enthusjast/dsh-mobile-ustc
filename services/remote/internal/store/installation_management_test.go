package store

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestInstallationManagementCursorRejectsOtherDirectoryPurposesAndAmbiguousJSON(t *testing.T) {
	cursor := installationDirectoryCursor{Version: 1, Purpose: "installation-directory-v1", UserID: "22222222-2222-4222-8222-222222222222", ProofKeyJKT: strings.Repeat("A", 43), Before: time.Now().UTC(), BeforeID: managedInstallation}
	raw, _ := json.Marshal(cursor)
	if _, err := parseInstallationDirectoryCursor(base64.RawURLEncoding.EncodeToString(raw)); err != nil {
		t.Fatal(err)
	}
	cursor.Purpose = "device-directory-v1"
	wrong, _ := json.Marshal(cursor)
	for _, encoded := range []string{"", strings.Repeat("a", 1025), base64.RawURLEncoding.EncodeToString(raw) + "=", base64.RawURLEncoding.EncodeToString(wrong), base64.RawURLEncoding.EncodeToString([]byte(`{"v":1,"v":1}`))} {
		if _, err := parseInstallationDirectoryCursor(encoded); err == nil {
			t.Fatal("invalid installation cursor accepted")
		}
	}
}
