package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"dsh-mobile-ustc/services/remote/internal/relay"
)

func TestNodeQueueLimitsAreProtectedStrictAndOffline(t *testing.T) {
	t.Setenv("REMOTE_RELAY_QUEUE_LIMITS_FILE", "")
	t.Setenv("REMOTE_DATABASE_URL", "PRIVATE_INVALID_DSN")
	var output bytes.Buffer
	if err := runSendQueueDescription([]string{"describe"}, &output); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Limits relay.SendQueueLimits `json:"limits"`
	}
	if json.Unmarshal(output.Bytes(), &result) != nil || result.Limits != relay.DefaultSendQueueLimits() {
		t.Fatal("offline defaults did not describe the node payload limits")
	}
	path := filepath.Join(t.TempDir(), "queues.json")
	good := []byte(`{"v":1,"ordinary_bytes":131072,"control_bytes":65536}`)
	if err := os.WriteFile(path, good, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REMOTE_RELAY_QUEUE_LIMITS_FILE", path)
	output.Reset()
	if err := runSendQueueDescription([]string{"describe"}, &output); err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(output.Bytes(), &result) != nil || result.Limits.OrdinaryBytes != 131072 || result.Limits.ControlBytes != 65536 {
		t.Fatal("protected node payload limits were not loaded")
	}
	for _, args := range [][]string{nil, {"status"}, {"replace"}, {"describe", "extra"}, {"describe", "--unknown"}} {
		output.Reset()
		if err := runSendQueueDescription(args, &output); err == nil || output.Len() != 0 {
			t.Fatal("invalid offline command emitted limits", args)
		}
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSendQueueLimits(path); err == nil {
		t.Fatal("node memory limits accepted a public file")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"v":1,"ordinary_bytes":0,"control_bytes":65536}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSendQueueLimits(path); err == nil {
		t.Fatal("invalid protected node memory limits accepted")
	}
}
