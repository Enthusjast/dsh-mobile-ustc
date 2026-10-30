package store

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestDeviceDirectoryCursorRejectsAmbiguousOrUnboundedLocators(t *testing.T) {
	value := deviceDirectoryCursor{Version: 1, UserID: "22222222-2222-4222-8222-222222222222", ProofKeyJKT: strings.Repeat("A", 43), Before: time.Now().UTC(), BeforeID: "44444444-4444-4444-8444-444444444444"}
	raw, _ := json.Marshal(value)
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	if got, err := parseDeviceDirectoryCursor(encoded); err != nil || got.UserID != value.UserID || !got.Before.Equal(value.Before) {
		t.Fatal("valid cursor rejected", err)
	}
	for _, invalid := range []string{"", encoded + "=", strings.Repeat("a", 1025), base64.RawURLEncoding.EncodeToString([]byte(`{"v":1,"v":1}`)), base64.RawURLEncoding.EncodeToString([]byte(`{"v":1,"user_id":"invalid"}`))} {
		if _, err := parseDeviceDirectoryCursor(invalid); err == nil {
			t.Fatal("invalid cursor accepted")
		}
	}
}
