package files

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSharedHostFileOfferHasTheGoPublicShape(t *testing.T) {
	_, source, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(source), "../../../../contracts/ws/v1/golden/file.offer.json"))
	if err != nil {
		t.Fatal(err)
	}
	var frame struct {
		V         int       `json:"v"`
		Type      string    `json:"type"`
		RequestID string    `json:"request_id"`
		RuntimeID string    `json:"runtime_id"`
		Epoch     string    `json:"runtime_epoch"`
		SessionID string    `json:"session_id"`
		Payload   FileOffer `json:"payload"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&frame); err != nil {
		t.Fatal(err)
	}
	offer := frame.Payload
	if frame.Type != "file.offer" || frame.V != 1 || len(offer.DownloadToken) != 43 || offer.UserID == "" || offer.DeviceID == "" || offer.KeyVersion != 1 || offer.GrantVersion != 3 || !offer.LeaseUntil.Before(offer.ExpiresAt) {
		t.Fatal("incomplete offer golden")
	}
	if _, err := NormalizeRegistration(UploadRegistration{RequestID: frame.RequestID, RuntimeID: frame.RuntimeID, SessionID: frame.SessionID, Name: offer.Name, SizeBytes: offer.SizeBytes, SHA256: offer.SHA256}); err != nil {
		t.Fatal(err)
	}
}
