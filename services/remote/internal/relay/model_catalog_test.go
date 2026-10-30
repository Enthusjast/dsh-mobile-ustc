package relay

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/store"
)

func TestModelCatalogReadUsesCurrentSubscriptionAndCorrelatesOnlyItsOwnResponse(t *testing.T) {
	const installation = "11111111-1111-4111-8111-111111111111"
	const runtime = "33333333-3333-4333-8333-333333333333"
	const epoch = "44444444-4444-4444-8444-444444444444"
	const session = "55555555-5555-4555-8555-555555555555"
	const request = "66666666-6666-4666-8666-666666666666"
	const sync = "77777777-7777-4777-8777-777777777777"
	for _, scenario := range []string{"success", "scope", "host-capability", "device-capability", "revoked", "invalid-body", "bounded", "timeout"} {
		t.Run(scenario, func(t *testing.T) {
			key := relayTestKey(t)
			jwk, jkt := relayTestPublicJWK(t, key)
			fake := &relayTestStore{ticket: store.TicketRedemption{UserID: installation, DeviceID: "22222222-2222-4222-8222-222222222222", RuntimeID: runtime, DeviceKeyVersion: 1, GrantVersion: 1, ProofPublicJWK: jwk, ProofKeyThumbprint: jkt, ExpiresAt: time.Now().Add(time.Minute), Scope: store.GrantScope{Actions: []string{"session.read", "session.model.select"}, Sessions: []string{session}, Workspaces: []string{}}}, hostCredential: store.HostCredentialIdentity{InstallationID: installation, KeyVersion: 1, PublicJWK: jwk, KeyThumbprint: jkt, ExpiresAt: time.Now().Add(time.Minute)}, detached: make(chan store.RuntimeConnection, 1)}
			if scenario == "scope" {
				fake.ticket.Scope.Actions = []string{"session.read"}
			}
			relay := New(fake)
			http := httptest.NewServer(relay)
			defer http.Close()
			hostCaps := []string{"command.relay.v1", "connection.heartbeat.v1", "session.read.v1", modelCatalogCapability}
			deviceCaps := append([]string{}, hostCaps...)
			if scenario == "host-capability" {
				hostCaps = hostCaps[:3]
			}
			if scenario == "device-capability" {
				deviceCaps = deviceCaps[:3]
			}
			host := dialRelayHost(t, http.URL, key, installation, runtime, epoch, hostCaps...)
			defer host.CloseNow()
			device := dialRelayDevice(t, http.URL, key, fake.ticket, runtime, deviceCaps...)
			defer device.CloseNow()
			writeWireFrame(t, device, map[string]any{"v": 1, "type": "session.subscribe", "request_id": request, "runtime_id": runtime, "session_id": session, "payload": map[string]any{}})
			ack := readEnvelope(t, device)
			_ = readEnvelope(t, host)
			base := map[string]any{"v": 1, "request_id": request, "runtime_id": runtime, "runtime_epoch": epoch, "session_id": session, "subscription_id": ack.SubscriptionID, "sync_id": sync, "type": "session.snapshot", "payload": map[string]any{"cursor": 0, "records": []any{}, "has_more": false, "assistant": nil}}
			writeWireFrame(t, host, base)
			_ = readEnvelope(t, device)
			id := "88888888-8888-4888-8888-888888888888"
			get := map[string]any{"v": 1, "type": "session.models.get", "request_id": id, "runtime_id": runtime, "runtime_epoch": epoch, "session_id": session, "subscription_id": ack.SubscriptionID, "payload": map[string]any{"sync_id": sync, "limit": 1}}
			if scenario == "invalid-body" {
				get["payload"] = map[string]any{"sync_id": sync, "limit": 1, "cursor": nil}
			}
			writeWireFrame(t, device, get)
			if scenario == "scope" || scenario == "host-capability" || scenario == "device-capability" || scenario == "invalid-body" {
				want := "protocol.unsupported"
				if scenario == "scope" {
					want = "access.denied"
				}
				if scenario == "invalid-body" {
					want = "protocol.invalid"
				}
				if denied := readEnvelope(t, device); denied.Type != "error" || denied.Payload["code"] != want {
					t.Fatal("unauthorized model read", denied)
				}
				writeEnvelope(t, host, "ping", map[string]any{})
				if frame := readEnvelope(t, host); frame.Type != "pong" {
					t.Fatal("denied read reached Host", frame)
				}
				return
			}
			forward := readEnvelope(t, host)
			if forward.Type != "session.models.get" || forward.RequestID == id || forward.SubscriptionID != ack.SubscriptionID {
				t.Fatal("read lost private correlation", forward)
			}
			if scenario == "timeout" {
				ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
				_, raw, err := device.Read(ctx)
				cancel()
				var timeout testEnvelope
				if err != nil || json.Unmarshal(raw, &timeout) != nil || timeout.Type != "session.models.error" || timeout.RequestID != id || timeout.Payload["code"] != "runtime.offline" {
					t.Fatal("silent Host did not release pending model read", timeout, err)
				}
				old := forward.RequestID
				writeWireFrame(t, device, get)
				forward = readEnvelope(t, host)
				if forward.RequestID == old {
					t.Fatal("timed out read identity reused")
				}
				late := map[string]any{"v": 1, "type": "session.models.error", "request_id": old, "runtime_id": runtime, "runtime_epoch": epoch, "session_id": session, "subscription_id": ack.SubscriptionID, "sync_id": sync, "payload": map[string]string{"code": "internal"}}
				writeWireFrame(t, host, late)
			}
			if scenario == "bounded" {
				get["request_id"] = "99999999-9999-4999-8999-999999999999"
				writeWireFrame(t, device, get)
				_ = readEnvelope(t, host)
				get["request_id"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
				writeWireFrame(t, device, get)
				if frame := readEnvelope(t, device); frame.Type != "error" || frame.Payload["code"] != "rate.limited" {
					t.Fatal("pending model reads unbounded", frame)
				}
			}
			if scenario == "revoked" {
				fake.mu.Lock()
				fake.readErr = store.ErrAccessDenied
				fake.mu.Unlock()
			}
			base["type"], base["request_id"], base["payload"] = "session.models.result", forward.RequestID, map[string]any{"items": []any{map[string]any{"provider": map[string]any{"id": "fixture", "label": "Offline"}, "model": map[string]any{"id": "fixture", "label": "模型"}, "reasoning_efforts": []any{}}}, "next_cursor": nil, "unavailable_provider_count": 0}
			writeWireFrame(t, host, base)
			frame := readEnvelope(t, device)
			if scenario == "revoked" {
				if frame.Type != "session.error" || frame.Payload["code"] != "access.denied" {
					t.Fatal("revoked model page leaked", frame)
				}
				return
			}
			if frame.Type != "session.models.result" || frame.RequestID != id || frame.SyncID != sync {
				t.Fatal("page crossed read identity", frame)
			}
			if scenario == "success" {
				writeWireFrame(t, device, get)
				replacement := readEnvelope(t, host)
				if replacement.RequestID == forward.RequestID {
					t.Fatal("reused client request inherited old private route")
				}
				writeWireFrame(t, host, base) // Late result for the previous generation.
				base["request_id"] = replacement.RequestID
				writeWireFrame(t, host, base)
				if frame := readEnvelope(t, device); frame.Type != "session.models.result" || frame.RequestID != id {
					t.Fatal("replacement page lost its route", frame)
				}
			}
		})
	}
}

func TestModelCatalogPageRejectsPrivateFieldsAndInvalidBudgets(t *testing.T) {
	good := `{"items":[{"provider":{"id":"fixture","label":"Offline"},"model":{"id":"fixture","label":"模型"},"reasoning_efforts":[]}],"next_cursor":null,"unavailable_provider_count":0}`
	if !validModelPage(json.RawMessage(good), 1) {
		t.Fatal("valid metadata rejected")
	}
	for _, raw := range []string{strings.Replace(good, `"next_cursor":null,`, "", 1), strings.Replace(good, `"reasoning_efforts":[]`, `"reasoning_efforts":null`, 1), strings.Replace(good, `"unavailable_provider_count":0`, `"api_key":"private","unavailable_provider_count":0`, 1), strings.Replace(good, `"Offline"`, `"`+strings.Repeat("x", 257)+`"`, 1)} {
		if validModelPage(json.RawMessage(raw), 1) {
			t.Fatal("private, missing or unbounded fields accepted")
		}
	}
}
