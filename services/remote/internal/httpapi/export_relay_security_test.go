package httpapi_test

import (
	"encoding/json"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/files"
)

func exportFrame(h *fileHTTPFixture, host *fileHost, kind, request string, payload any) map[string]any {
	return map[string]any{"v": 1, "type": kind, "request_id": request, "runtime_id": fileRuntimeID, "runtime_epoch": host.epoch, "session_id": h.session, "payload": payload}
}
func TestExportRelaySeparatesSocketScopeAndServerOperationIdentity(t *testing.T) {
	h := newFileHTTPFixture(t)
	host := connectFileHost(t, h, files.ExportCapability)
	if _, err := h.database.ExecContext(h.ctx, `update runtime_grants set scope=jsonb_set(scope,'{sessions}',jsonb_build_array($1::text))`, h.session); err != nil {
		t.Fatal(err)
	}
	phone := connectExportPhone(t, h, h.caller, h.token, "33333333-3333-4333-8333-333333333333", false)
	request := exportTestUUID(t)
	phone.send(t, exportFrame(h, host, "file.exports.list", request, map[string]any{}))
	forward := host.read(t)
	var operation string
	_ = json.Unmarshal(forward["request_id"], &operation)
	var lease struct {
		User      string    `json:"user_id"`
		Device    string    `json:"device_id"`
		Workspace bool      `json:"allow_workspace"`
		Until     time.Time `json:"lease_until"`
		Expires   time.Time `json:"expires_at"`
	}
	if string(forward["type"]) != `"file.exports.list"` || json.Unmarshal(forward["payload"], &lease) != nil || operation == request || lease.User != "22222222-2222-4222-8222-222222222222" || lease.Device != "33333333-3333-4333-8333-333333333333" || lease.Workspace || lease.Until.After(time.Now().Add(5*time.Second)) {
		t.Fatal("forwarded authority was not derived from the narrow authenticated socket")
	}
	host.send(t, exportFrame(h, host, "file.exports.result", operation, map[string]any{"items": []any{map[string]any{"source_id": exportTestUUID(t), "kind": "directory", "origin": "workspace_artifact", "name": "must not appear", "expires_at": lease.Expires}}, "directory_id": nil, "cursor": nil}))
	if nativeExportError(t, phone.read(t)) != "protocol.invalid" {
		t.Fatal("Host workspace catalog crossed a session-only socket scope")
	}
}

func TestExportRelayRejectsPhoneAuthorityAndPathsBeforeHostDispatch(t *testing.T) {
	h := newFileHTTPFixture(t)
	host := connectFileHost(t, h, files.ExportCapability)
	phone := connectExportPhone(t, h, h.caller, h.token, "33333333-3333-4333-8333-333333333333", true)
	for _, payload := range []map[string]any{{"source_id": nil}, {"directory_id": nil}, {"allow_workspace": true}, {"user_id": "22222222-2222-4222-8222-222222222222"}, {"path": "/private"}} {
		phone.send(t, exportFrame(h, host, "file.exports.list", exportTestUUID(t), payload))
		if nativeExportError(t, phone.read(t)) != "protocol.invalid" {
			t.Fatal("phone supplied Host selectors or authority")
		}
	}
	host.send(t, map[string]any{"v": 1, "type": "ping", "payload": map[string]any{}})
	if string(host.read(t)["type"]) != `"pong"` {
		t.Fatal("invalid source request reached the Host")
	}
}

func TestExportRelayRenewalCannotUpgradeAnExistingGrant(t *testing.T) {
	h := newFileHTTPFixture(t)
	host := connectFileHost(t, h, files.ExportCapability)
	phone := connectExportPhone(t, h, h.caller, h.token, "33333333-3333-4333-8333-333333333333", true)
	phone.send(t, exportFrame(h, host, "file.exports.list", exportTestUUID(t), map[string]any{}))
	forward := host.read(t)
	var operation string
	_ = json.Unmarshal(forward["request_id"], &operation)
	if _, err := h.database.ExecContext(h.ctx, `update runtime_grants set grant_version=grant_version+1`); err != nil {
		t.Fatal(err)
	}
	host.send(t, map[string]any{"v": 1, "type": "file.export.renew", "request_id": exportTestUUID(t), "runtime_id": fileRuntimeID, "runtime_epoch": host.epoch, "payload": map[string]any{"operation_ids": []string{operation}}})
	if nativeExportError(t, phone.read(t)) != "access.denied" {
		t.Fatal("export request survived its original grant generation")
	}
	for i := 0; i < 2; i++ {
		frame := host.read(t)
		if string(frame["type"]) == `"file.export.renewed"` {
			var payload struct {
				Leases []any `json:"leases"`
			}
			_ = json.Unmarshal(frame["payload"], &payload)
			if len(payload.Leases) != 0 {
				t.Fatal("renewal revived cancelled authority")
			}
			return
		}
	}
	t.Fatal("renewal response missing")
}

func TestExportRelayUploadCannotRunAheadOfItsBoundManifest(t *testing.T) {
	h := newFileHTTPFixture(t)
	host := connectFileHost(t, h, files.ExportCapability)
	phone := connectExportPhone(t, h, h.caller, h.token, "33333333-3333-4333-8333-333333333333", true)
	phone.send(t, exportFrame(h, host, "file.export.request", exportTestUUID(t), map[string]any{"source_id": exportTestUUID(t)}))
	forward := host.read(t)
	var operation string
	_ = json.Unmarshal(forward["request_id"], &operation)
	host.send(t, exportFrame(h, host, "file.export.uploaded", operation, map[string]any{"file_id": exportTestUUID(t)}))
	if nativeExportError(t, phone.read(t)) != "protocol.invalid" {
		t.Fatal("upload attestation preceded source registration")
	}
	var count int
	if err := h.database.QueryRowContext(h.ctx, `select count(*) from files`).Scan(&count); err != nil || count != 0 {
		t.Fatal("out-of-order upload left file authority")
	}
}
