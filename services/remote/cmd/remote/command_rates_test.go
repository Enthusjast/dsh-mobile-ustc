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

func TestCommandAdmissionDeploymentDefaultsAndStrictPolicyFile(t *testing.T) {
	if limits, err := loadCommandRateLimits(""); err != nil || limits != store.DefaultCommandRateLimits() {
		t.Fatal("production command limits have no default", limits, err)
	}
	path := filepath.Join(t.TempDir(), "command-limits.json")
	good := `{"v":1,"window_ms":1000,"user":60,"device":20,"installation":120,"session":20}`
	for _, raw := range []string{good, strings.Replace(good, `"device":20`, `"Device":20`, 1), strings.Replace(good, `"device":20`, `"device":20,"Device":100`, 1), strings.Replace(good, `"v":1`, `"v":2`, 1), strings.Replace(good, `"device":20`, `"device":0`, 1), strings.Replace(good, `"window_ms":1000`, `"window_ms":99`, 1), strings.Replace(good, `"user":60`, `"user":100001`, 1), strings.Replace(good, `"session":20`, `"session":null`, 1), strings.Replace(good, `"v":1`, `"v":1,"v":1`, 1), strings.Replace(good, `"session":20`, `"session":20,"unknown":1`, 1)} {
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := loadCommandRateLimits(path)
		if (err == nil) != (raw == good) {
			t.Fatal("deployment policy validation mismatch", err)
		}
	}
	if err := os.WriteFile(path, []byte(good), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCommandRateLimits(path); err == nil {
		t.Fatal("unprotected limits policy accepted")
	}
}

func TestCommandLimitsDescriptionIsReadOnlyAndUsesCanonicalPolicyDigest(t *testing.T) {
	t.Setenv("REMOTE_COMMAND_LIMITS_FILE", "")
	var output bytes.Buffer
	if err := runCommandRateDescription([]string{"describe"}, &output); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Policy store.CommandRateLimits `json:"policy"`
		Hash   string                  `json:"policy_sha256"`
	}
	if json.Unmarshal(output.Bytes(), &result) != nil || result.Policy != store.DefaultCommandRateLimits() || len(result.Hash) != 64 {
		t.Fatal("invalid policy description")
	}
	for _, args := range [][]string{{}, {"configure"}, {"describe", "--unknown"}, {"describe", "extra"}} {
		output.Reset()
		if err := runCommandRateDescription(args, &output); err == nil || output.Len() != 0 {
			t.Fatal("invalid policy command produced output", args)
		}
	}
}
