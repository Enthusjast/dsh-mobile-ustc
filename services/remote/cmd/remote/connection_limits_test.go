package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dsh-mobile-ustc/services/remote/internal/store"
)

func TestConnectionLimitsDeploymentDefaultsAndStrictFields(t *testing.T) {
	if limits, err := loadConnectionLimits(""); err != nil || limits != store.DefaultConnectionLimits() {
		t.Fatal("connection budget defaults unavailable", limits, err)
	}
	good := `{"v":1,"total":10,"user":10,"device":2,"installation":10,"pending_handshakes":4}`
	path := filepath.Join(t.TempDir(), "connections.json")
	for _, raw := range []string{good, strings.Replace(good, `"v":1`, `"v":2`, 1), strings.Replace(good, `"device":2`, `"device":11`, 1), strings.Replace(good, `"device":2`, `"Device":2`, 1), strings.Replace(good, `"total":10`, `"total":0`, 1), strings.Replace(good, `"pending_handshakes":4`, `"pending_handshakes":null`, 1), strings.Replace(good, `"device":2`, `"device":2,"device":2`, 1)} {
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := loadConnectionLimits(path)
		if (err == nil) != (raw == good) {
			t.Fatal("connection budget policy validation mismatch", err)
		}
	}
	if err := os.WriteFile(path, []byte(good), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConnectionLimits(path); err == nil {
		t.Fatal("publicly readable budget policy accepted")
	}
}

func TestConnectionLimitsDescriptionIsOfflineAndContainsOnlyPolicyMetadata(t *testing.T) {
	t.Setenv("REMOTE_CONNECTION_LIMITS_FILE", "")
	t.Setenv("REMOTE_DATABASE_URL", "PRIVATE_INVALID_DATABASE")
	var output bytes.Buffer
	if err := runConnectionLimitDescription([]string{"describe"}, &output); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Policy store.ConnectionLimits `json:"policy"`
		Hash   string                 `json:"policy_sha256"`
	}
	if json.Unmarshal(output.Bytes(), &result) != nil || result.Policy != store.DefaultConnectionLimits() || len(result.Hash) != 64 {
		t.Fatal("invalid offline connection policy description")
	}
	for _, args := range [][]string{nil, {"status"}, {"describe", "extra"}, {"describe", "--unknown"}} {
		output.Reset()
		if err := runConnectionLimitDescription(args, &output); err == nil || output.Len() != 0 {
			t.Fatal("invalid description command produced output", args)
		}
	}
}
