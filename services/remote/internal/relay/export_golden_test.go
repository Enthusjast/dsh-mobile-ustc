package relay

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/files"
)

func TestExportGoldenFramesKeepPrivateAuthorityOutOfPhoneSelectors(t *testing.T) {
	_, source, _, _ := runtime.Caller(0)
	directory := filepath.Join(filepath.Dir(source), "../../../../contracts/ws/v1/golden")
	load := func(name string) wireEnvelope {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(directory, name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		frame, err := decodeWireFrame(raw)
		if err != nil {
			t.Fatal(err)
		}
		return frame
	}
	for _, name := range []string{"file.exports.list", "file.export.request", "file.export.cancel"} {
		frame := load(name)
		if !exportEnvelope(frame) {
			t.Fatal("invalid phone envelope")
		}
		var value exportRequest
		if decodePayload(frame.Payload, &value) != nil {
			t.Fatal("phone selector drifted")
		}
	}
	forward := load("file.export.request.forwarded")
	var lease struct {
		User      string    `json:"user_id"`
		Device    string    `json:"device_id"`
		Key       int64     `json:"key_version"`
		Grant     int64     `json:"grant_version"`
		Workspace bool      `json:"allow_workspace"`
		Until     time.Time `json:"lease_until"`
		Expires   time.Time `json:"expires_at"`
		Request   string    `json:"origin_request_id"`
		Source    string    `json:"source_id"`
	}
	if decodePayload(forward.Payload, &lease) != nil || lease.User == "" || lease.Device == "" || lease.Key != 1 || lease.Grant != 7 || !lease.Until.Before(lease.Expires) {
		t.Fatal("Host lease provenance drifted")
	}
	manifest := load("file.export.manifest")
	var body exportManifest
	if decodePayload(manifest.Payload, &body) != nil || body.Size == nil {
		t.Fatal("Host manifest drifted")
	}
	if _, err := files.NormalizeExport(files.ExportRegistration{Origin: body.Origin, RequestID: lease.Request, RuntimeID: manifest.RuntimeID, SessionID: manifest.SessionID, SourceID: body.Source, Name: body.Name, SizeBytes: *body.Size, SHA256: body.SHA, SourceExpiresAt: body.Expires}, files.HostBinding{RuntimeID: manifest.RuntimeID, RuntimeEpoch: manifest.RuntimeEpoch}); err != nil {
		t.Fatal(err)
	}
	prepared := load("file.export.upload")
	var upload files.UploadPrepared
	if decodePayload(prepared.Payload, &upload) != nil || upload.File.Direction != "from_host" || upload.Upload == nil {
		t.Fatal("Host-only upload capability shape drifted")
	}
	accepted := load("file.export.accepted")
	var result struct {
		File files.Status `json:"file"`
	}
	if decodePayload(accepted.Payload, &result) != nil || result.File.State != "scanning" {
		t.Fatal("phone receipt invented a completed download")
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(accepted.Payload, &fields)
	if _, ok := fields["upload"]; ok {
		t.Fatal("phone received an object capability")
	}
}
