package canonical

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestCanonicalJSONSharedVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../../contracts/security/jcs-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Name        string `json:"name"`
		Input       string `json:"input"`
		InputBase64 string `json:"input_base64"`
		Canonical   string `json:"canonical"`
		SHA256      string `json:"sha256"`
		Invalid     bool   `json:"invalid"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, vector := range vectors {
		t.Run(vector.Name, func(t *testing.T) {
			input := []byte(vector.Input)
			if vector.InputBase64 != "" {
				var err error
				input, err = base64.StdEncoding.DecodeString(vector.InputBase64)
				if err != nil {
					t.Fatal(err)
				}
			}
			encoded, err := Object(input)
			if vector.Invalid {
				if err == nil {
					t.Fatal("ambiguous input accepted")
				}
				return
			}
			if err != nil || string(encoded) != vector.Canonical {
				t.Fatalf("canonical=%q, want %q; error=%v", encoded, vector.Canonical, err)
			}
			digest := sha256.Sum256(encoded)
			if hex.EncodeToString(digest[:]) != vector.SHA256 {
				t.Fatal("cross-language digest mismatch")
			}
		})
	}
}

func TestCanonicalJSONBudget(t *testing.T) {
	for _, raw := range []string{`{"s":"` + strings.Repeat("x", MaxBytes) + `"}`, strings.Repeat(`{"a":`, 40) + `true` + strings.Repeat(`}`, 40), `{"nodes":[` + strings.Repeat(`0,`, 16384) + `0]}`} {
		if _, err := Object([]byte(raw)); err == nil {
			t.Fatal("signing budget was bypassed")
		}
	}
}
