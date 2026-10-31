package relay

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/store"
)

func TestMessagePreviewResultFromReplacedDatabaseHostCannotReachPhone(t *testing.T) {
	const installation = "11111111-1111-4111-8111-111111111111"
	const runtime = "33333333-3333-4333-8333-333333333333"
	const epoch = "44444444-4444-4444-8444-444444444444"
	const session = "55555555-5555-4555-8555-555555555555"
	const request = "66666666-6666-4666-8666-666666666666"
	const syncID = "77777777-7777-4777-8777-777777777777"
	const previewRequest = "88888888-8888-4888-8888-888888888888"
	key := relayTestKey(t)
	jwk, jkt := relayTestPublicJWK(t, key)
	database := &relayTestStore{
		ticket: store.TicketRedemption{UserID: installation, DeviceID: "22222222-2222-4222-8222-222222222222", RuntimeID: runtime,
			DeviceKeyVersion: 1, GrantVersion: 1, ProofPublicJWK: jwk, ProofKeyThumbprint: jkt, ExpiresAt: time.Now().Add(time.Minute),
			Scope: store.GrantScope{Actions: []string{"session.read"}, Sessions: []string{session}, Workspaces: []string{}}},
		hostCredential: store.HostCredentialIdentity{InstallationID: installation, KeyVersion: 1, PublicJWK: jwk, KeyThumbprint: jkt, ExpiresAt: time.Now().Add(time.Minute)},
		detached:       make(chan store.RuntimeConnection, 1),
	}
	server := httptest.NewServer(New(database))
	defer server.Close()
	caps := []string{"command.relay.v1", "connection.heartbeat.v1", "session.read.v1", messageActionsCapability}
	host := dialRelayHost(t, server.URL, key, installation, runtime, epoch, caps...)
	defer host.CloseNow()
	phone := dialRelayDevice(t, server.URL, key, database.ticket, runtime, caps...)
	defer phone.CloseNow()
	writeWireFrame(t, phone, map[string]any{"v": 1, "type": "session.subscribe", "request_id": request,
		"runtime_id": runtime, "session_id": session, "payload": map[string]any{}})
	subscription := readEnvelope(t, phone)
	_ = readEnvelope(t, host)
	frame := map[string]any{"v": 1, "type": "session.snapshot", "request_id": request, "runtime_id": runtime,
		"runtime_epoch": epoch, "session_id": session, "subscription_id": subscription.SubscriptionID, "sync_id": syncID,
		"payload": map[string]any{"cursor": 0, "records": []any{}, "has_more": false, "assistant": nil}}
	writeWireFrame(t, host, frame)
	_ = readEnvelope(t, phone)
	writeWireFrame(t, phone, map[string]any{"v": 1, "type": "session.message.preview.get", "request_id": previewRequest,
		"runtime_id": runtime, "runtime_epoch": epoch, "session_id": session, "subscription_id": subscription.SubscriptionID,
		"payload": map[string]any{"sync_id": syncID, "native_seq": 0}})
	forwarded := readEnvelope(t, host)
	if forwarded.Type != "session.message.preview.get" {
		t.Fatal("preview was not admitted before replacement", forwarded)
	}
	database.mu.Lock()
	database.touchErr = store.ErrAccessDenied
	database.mu.Unlock()
	frame["type"], frame["request_id"] = "session.message.preview.result", forwarded.RequestID
	frame["payload"] = map[string]any{"v": 1, "anchor": map[string]any{"v": 1, "subscription_id": subscription.SubscriptionID,
		"sync_id": syncID, "native_seq": 0, "message_version_sha256": strings.Repeat("a", 64), "anchor_sha256": strings.Repeat("b", 64)},
		"text": "obsolete producer text must not leave Relay", "shareable": true, "complete": true}
	writeWireFrame(t, host, frame)
	result := readEnvelope(t, phone)
	if result.Type != "session.error" || result.Payload["code"] != "runtime.changed" {
		t.Fatal("replaced Host result reached the phone", result)
	}
}
