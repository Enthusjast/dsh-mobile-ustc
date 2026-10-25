package relay

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestFileMessageDigestMatchesSharedNodeGolden(t *testing.T) {
	_, source, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(source), "../../../../contracts/ws/v1/golden/message-file-submit.forwarded.json"))
	if err != nil {
		t.Fatal(err)
	}
	var frame struct {
		SessionID string          `json:"session_id"`
		Digest    string          `json:"payload_sha256"`
		Payload   json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(raw, &frame); err != nil {
		t.Fatal(err)
	}
	var payload messageSubmitPayload
	if err := decodePayload(frame.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if err := normalizeMessageSubmit(payload); err != nil {
		t.Fatal(err)
	}
	digest, err := messageSubmitDigest(frame.SessionID, payload)
	if err != nil || digest != frame.Digest {
		t.Fatal("Node/Go file message digest disagrees")
	}
	reconcileRaw, err := os.ReadFile(filepath.Join(filepath.Dir(source), "../../../../contracts/ws/v1/golden/message-file-reconcile.forwarded.json"))
	if err != nil {
		t.Fatal(err)
	}
	var reconcile struct {
		Type      string          `json:"type"`
		SessionID string          `json:"session_id"`
		Digest    string          `json:"payload_sha256"`
		Payload   json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(reconcileRaw, &reconcile); err != nil {
		t.Fatal(err)
	}
	var original messageSubmitPayload
	if err := decodePayload(reconcile.Payload, &original); err != nil {
		t.Fatal(err)
	}
	originalDigest, _ := messageSubmitDigest(reconcile.SessionID, original)
	if reconcile.Type != "message.files.reconcile" || originalDigest != reconcile.Digest || originalDigest != digest {
		t.Fatal("reconciliation changed the original message digest")
	}
	for _, raw := range []string{
		`{"mode":"queue","content":[{"type":"file","file_id":"cccccccc-cccc-4ccc-8ccc-cccccccccccc","text":""}]}`,
		`{"mode":"queue","content":[{"type":"text","text":"ok","file_id":""}]}`,
		`{"mode":"queue","content":[{"type":"file","receiptId":"private"}]}`,
		`{"mode":"queue","content":[{"type":"file","path":"/private"}]}`,
		`{"mode":"queue","content":[{"type":"file","file_id":"cccccccc-cccc-4ccc-8ccc-cccccccccccc"},{"type":"file","file_id":"cccccccc-cccc-4ccc-8ccc-cccccccccccc"}]}`,
	} {
		var invalid messageSubmitPayload
		if decodePayload([]byte(raw), &invalid) == nil && normalizeMessageSubmit(invalid) == nil {
			t.Fatal("unsafe file part admitted")
		}
	}
}
