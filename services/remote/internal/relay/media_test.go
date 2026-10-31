package relay

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/files"
	"dsh-mobile-ustc/services/remote/internal/store"
)

type mediaTestStore struct {
	*relayTestStore
	exportReads  atomic.Int64
	exportDenied atomic.Bool
}

func (database *mediaTestStore) AuthorizeRealtimeExport(_ context.Context, ticket store.TicketRedemption, _ string) (files.ExportAccess, error) {
	database.exportReads.Add(1)
	if database.exportDenied.Load() {
		return files.ExportAccess{}, store.ErrAccessDenied
	}
	return files.ExportAccess{UserID: ticket.UserID, DeviceKeyVersion: ticket.DeviceKeyVersion, GrantVersion: ticket.GrantVersion, LeaseUntil: time.Now().Add(5 * time.Second)}, nil
}
func (database *mediaTestStore) LookupRealtimeExport(context.Context, store.TicketRedemption, files.ExportSelector) (files.Status, bool, error) {
	return files.Status{}, false, nil
}

func TestMediaReferenceStrictlyBoundsRasterAndRejectsAuthorityFields(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	valid := mediaReference{Version: 1, Origin: "session_attachment", Seq: 0, Index: 0, EventVersion: strings.Repeat("a", 64),
		Manifest: mediaManifest{Name: "image.png", Size: 80, SHA: strings.Repeat("b", 64)}, MediaType: "image/png", Width: 1, Height: 1}
	if !validMediaReference(valid, id, id, id) {
		t.Fatal("valid media reference rejected")
	}
	for _, change := range []func(*mediaReference){
		func(ref *mediaReference) { ref.Version = 2 }, func(ref *mediaReference) { ref.Origin = "workspace_artifact" },
		func(ref *mediaReference) { ref.Index = -1 }, func(ref *mediaReference) { ref.Seq = 9_007_199_254_740_992 },
		func(ref *mediaReference) { ref.MediaType = "image/svg+xml" }, func(ref *mediaReference) { ref.Width = 8000; ref.Height = 8000 },
		func(ref *mediaReference) { ref.Manifest.Size = maxImageBytes + 1 }, func(ref *mediaReference) { ref.Manifest.Name = "../image.png" },
		func(ref *mediaReference) { ref.EventVersion = strings.Repeat("A", 64) },
	} {
		ref := valid
		change(&ref)
		if validMediaReference(ref, id, id, id) {
			t.Fatal("invalid media reference admitted", ref)
		}
	}
	encoded, _ := json.Marshal(valid)
	for _, field := range []string{`"url":"https://invalid.example/image",`, `"attachment_id":"sha256:private",`, `"file_id":"` + id + `",`} {
		var ref mediaReference
		if decodePayload(append([]byte("{"+field), encoded[1:]...), &ref) == nil {
			t.Fatal("media display reference acquired authority")
		}
	}
	var missing mediaReference
	if decodePayload([]byte(`{"v":1,"origin":"session_attachment","part_index":0,"event_version_sha256":"`+strings.Repeat("a", 64)+`","manifest":{"name":"image.png","size_bytes":1,"sha256":"`+strings.Repeat("b", 64)+`"},"media_type":"image/png","width":1,"height":1}`), &missing) == nil {
		t.Fatal("missing native sequence became zero")
	}
}

func TestMediaResolveIndependentlyAuthorizesExportAndBindsExactReaderReference(t *testing.T) {
	const installation = "11111111-1111-4111-8111-111111111111"
	const runtime = "33333333-3333-4333-8333-333333333333"
	const epoch = "44444444-4444-4444-8444-444444444444"
	const session = "55555555-5555-4555-8555-555555555555"
	const request = "66666666-6666-4666-8666-666666666666"
	const syncID = "77777777-7777-4777-8777-777777777777"
	const mediaRequest = "88888888-8888-4888-8888-888888888888"
	for _, scenario := range []string{"success", "no-download-grant", "host-capability", "device-capability", "forged-reference", "revoke-before-result", "retired-reader", "bounded", "timeout"} {
		t.Run(scenario, func(t *testing.T) {
			key := relayTestKey(t)
			jwk, jkt := relayTestPublicJWK(t, key)
			database := &mediaTestStore{relayTestStore: &relayTestStore{ticket: store.TicketRedemption{UserID: installation,
				DeviceID: "22222222-2222-4222-8222-222222222222", RuntimeID: runtime, DeviceKeyVersion: 1, GrantVersion: 7,
				ProofPublicJWK: jwk, ProofKeyThumbprint: jkt, ExpiresAt: time.Now().Add(time.Minute),
				Scope: store.GrantScope{Actions: []string{"session.read", "file.download"}, Sessions: []string{session}, Workspaces: []string{}}},
				hostCredential: store.HostCredentialIdentity{InstallationID: installation, KeyVersion: 1, PublicJWK: jwk, KeyThumbprint: jkt, ExpiresAt: time.Now().Add(time.Minute)}, detached: make(chan store.RuntimeConnection, 1)}}
			if scenario == "no-download-grant" {
				database.ticket.Scope.Actions = []string{"session.read"}
			}
			relay := New(database)
			relay.exports = &exportRouter{server: relay, database: database}
			http := httptest.NewServer(relay)
			defer http.Close()
			hostCaps := []string{"connection.heartbeat.v1", "session.read.v1", "session.catalog.v1", files.ExportCapability, sessionMediaCapability}
			deviceCaps := append([]string{}, hostCaps...)
			if scenario == "host-capability" {
				hostCaps = hostCaps[:4]
			}
			if scenario == "device-capability" {
				deviceCaps = deviceCaps[:4]
			}
			host := dialRelayHost(t, http.URL, key, installation, runtime, epoch, hostCaps...)
			defer host.CloseNow()
			phone := dialRelayDevice(t, http.URL, key, database.ticket, runtime, deviceCaps...)
			defer phone.CloseNow()
			writeWireFrame(t, phone, map[string]any{"v": 1, "type": "session.subscribe", "request_id": request, "runtime_id": runtime, "session_id": session, "payload": map[string]any{}})
			ack := readEnvelope(t, phone)
			forwardedSubscribe := readEnvelope(t, host)
			if scenario != "host-capability" && scenario != "device-capability" && forwardedSubscribe.Payload["media_refs"] != true {
				t.Fatal("media projection was not explicitly negotiated")
			}
			base := map[string]any{"v": 1, "type": "session.snapshot", "request_id": request, "runtime_id": runtime, "runtime_epoch": epoch, "session_id": session, "subscription_id": ack.SubscriptionID, "sync_id": syncID, "payload": map[string]any{"cursor": 0, "records": []any{}, "has_more": false, "assistant": nil}}
			writeWireFrame(t, host, base)
			_ = readEnvelope(t, phone)
			reference := mediaReference{Version: 1, Origin: "session_attachment", Seq: 0, Index: 0, EventVersion: strings.Repeat("a", 64), Manifest: mediaManifest{Name: "image.png", Size: 80, SHA: strings.Repeat("b", 64)}, MediaType: "image/png", Width: 1, Height: 1}
			get := map[string]any{"v": 1, "type": "session.media.resolve", "request_id": mediaRequest, "runtime_id": runtime, "runtime_epoch": epoch, "session_id": session, "subscription_id": ack.SubscriptionID, "payload": map[string]any{"sync_id": syncID, "reference": reference}}
			writeWireFrame(t, phone, get)
			if scenario == "no-download-grant" || scenario == "host-capability" || scenario == "device-capability" {
				denied := readEnvelope(t, phone)
				if denied.Type != "error" || denied.Payload["code"] != "access.denied" && denied.Payload["code"] != "protocol.unsupported" {
					t.Fatal("unauthorized media resolve admitted", denied)
				}
				if database.exportReads.Load() != 0 {
					t.Fatal("denied capability/grant reached export producer")
				}
				return
			}
			forward := readEnvelope(t, host)
			if forward.Type != "session.media.resolve" || forward.RequestID == mediaRequest || forward.Payload["allow_workspace"] != false || forward.Payload["user_id"] != installation || forward.Payload["grant_version"] != float64(7) {
				t.Fatal("media request lost independent export authority", forward)
			}
			if scenario == "timeout" {
				ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
				_, raw, err := phone.Read(ctx)
				cancel()
				var timed testEnvelope
				if err != nil || json.Unmarshal(raw, &timed) != nil || timed.Type != "session.media.error" || timed.RequestID != mediaRequest || timed.SyncID != syncID || timed.Payload["code"] != "runtime.offline" {
					t.Fatal("media timeout retained authority", timed, err)
				}
				return
			}
			if scenario == "bounded" {
				get["request_id"] = "99999999-9999-4999-8999-999999999999"
				writeWireFrame(t, phone, get)
				_ = readEnvelope(t, host)
				get["request_id"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
				writeWireFrame(t, phone, get)
				if denied := readEnvelope(t, phone); denied.Type != "error" || denied.Payload["code"] != "rate.limited" {
					t.Fatal("unbounded media resolver", denied)
				}
			}
			if scenario == "revoke-before-result" {
				database.exportDenied.Store(true)
			}
			if scenario == "forged-reference" {
				reference.Manifest.SHA = strings.Repeat("c", 64)
			}
			if scenario == "retired-reader" {
				writeWireFrame(t, phone, map[string]any{"v": 1, "type": "session.unsubscribe", "request_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "runtime_id": runtime, "runtime_epoch": epoch, "session_id": session, "subscription_id": ack.SubscriptionID, "payload": map[string]any{}})
				_ = readEnvelope(t, host)
				_ = readEnvelope(t, phone)
			}
			base["type"], base["request_id"], base["payload"] = "session.media.result", forward.RequestID, map[string]any{"reference": reference, "source": map[string]any{"source_id": "cccccccc-cccc-4ccc-8ccc-cccccccccccc", "kind": "file", "origin": "session_attachment", "name": "image.png", "size_bytes": 80, "expires_at": time.Now().Add(30 * time.Second)}}
			writeWireFrame(t, host, base)
			if scenario == "retired-reader" {
				writeEnvelope(t, host, "ping", map[string]any{})
				if pong := readEnvelope(t, host); pong.Type != "pong" {
					t.Fatal("retired media response mutated Host connection", pong)
				}
				return
			}
			result := readEnvelope(t, phone)
			if scenario == "forged-reference" || scenario == "revoke-before-result" {
				if result.Type != "session.error" {
					t.Fatal("stale or forged media result leaked", result)
				}
				return
			}
			if result.Type != "session.media.result" || result.RequestID != mediaRequest || result.SyncID != syncID || database.exportReads.Load() < 2 {
				t.Fatal("media result skipped independent reauthorization", result)
			}
		})
	}
}
