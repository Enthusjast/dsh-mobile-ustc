package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestJWKSRejectsAmbiguousDocumentsWithoutReplacingVerifiedKeys(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	public := testRSAJWK(key, "known-key")
	encoded, err := json.Marshal(public)
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := json.Marshal(testRSAJWK(key, "unknown-key"))
	if err != nil {
		t.Fatal(err)
	}
	valid := []byte(fmt.Sprintf(`{"keys":[%s]}`, encoded))
	duplicateTop := []byte(fmt.Sprintf(`{"keys":[%s],"keys":[%s]}`, encoded, replacement))
	duplicateNested := []byte(fmt.Sprintf(`{"keys":[{"k\u0074y":"RSA",%s]}`, replacement[1:]))
	invalidUTF8 := append([]byte(fmt.Sprintf(`{"keys":[%s],"name":"`, replacement)), 0xff, '"', '}')
	tests := map[string][]byte{
		"duplicate top-level keys": duplicateTop,
		"duplicate escaped member": duplicateNested,
		"invalid UTF-8":            invalidUTF8,
		"non-object key":           []byte(`{"keys":[null]}`),
	}
	for _, name := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k", "jku", "x5u"} {
		candidate := testRSAJWK(key, "unknown-key")
		candidate[name] = nil
		bytes, err := json.Marshal(map[string]any{"keys": []any{candidate}})
		if err != nil {
			t.Fatal(err)
		}
		tests["private or remote member "+name] = bytes
	}
	for name, malformed := range tests {
		t.Run(name, func(t *testing.T) {
			var mu sync.Mutex
			body := valid
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				response.Header().Set("Cache-Control", "max-age=300")
				_, _ = response.Write(body)
			}))
			defer server.Close()
			now := time.Now()
			set, err := newKeySet(server.URL, server.Client(), func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			if _, err := set.get(context.Background(), "known-key", "RS256"); err != nil {
				t.Fatalf("valid key set rejected: %v", err)
			}
			mu.Lock()
			body = malformed
			mu.Unlock()
			if _, err := set.get(context.Background(), "unknown-key", "RS256"); err == nil {
				t.Fatal("malformed refresh accepted")
			}
			if _, err := set.get(context.Background(), "known-key", "RS256"); err != nil {
				t.Fatalf("malformed refresh replaced the previous key set: %v", err)
			}
			now = now.Add(6 * time.Minute)
			if _, err := set.get(context.Background(), "known-key", "RS256"); err == nil {
				t.Fatal("expired keys were reused after a malformed refresh")
			}
		})
	}
}
