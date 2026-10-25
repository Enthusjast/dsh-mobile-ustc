package relay

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/store"
)

func TestProtocolCloseRetiresAnUnresponsivePeerWithoutDelayingAnotherReceipt(t *testing.T) {
	key := relayTestKey(t)
	jwk, thumbprint := relayTestPublicJWK(t, key)
	const installation = "11111111-1111-4111-8111-111111111111"
	const runtime = "33333333-3333-4333-8333-333333333333"
	const epoch = "44444444-4444-4444-8444-444444444444"
	const session = "55555555-5555-4555-8555-555555555555"
	const request = "66666666-6666-4666-8666-666666666666"
	ticket := store.TicketRedemption{UserID: installation, DeviceID: "22222222-2222-4222-8222-222222222222", RuntimeID: runtime, GrantVersion: 1, DeviceKeyVersion: 1,
		ProofPublicJWK: jwk, ProofKeyThumbprint: thumbprint, ExpiresAt: time.Now().Add(time.Minute), Scope: store.GrantScope{Actions: []string{"message.submit"}, Sessions: []string{session}, Workspaces: []string{}}}
	fake := &relayTestStore{ticket: ticket, hostCredential: store.HostCredentialIdentity{InstallationID: installation, KeyVersion: 1, PublicJWK: jwk, KeyThumbprint: thumbprint, ExpiresAt: time.Now().Add(time.Minute)}, detached: make(chan store.RuntimeConnection, 1)}
	relay := New(fake)
	server := httptest.NewServer(relay)
	t.Cleanup(server.Close)
	host := dialRelayHost(t, server.URL, key, installation, runtime, epoch)
	defer host.CloseNow()
	phone := dialRelayDevice(t, server.URL, key, ticket, runtime)
	defer phone.CloseNow()
	broken := dialRelayDevice(t, server.URL, key, ticket, runtime)
	defer broken.CloseNow()
	payload := messageSubmitPayload{Mode: "queue", Content: []messageContent{{Type: "text", Text: "close isolation fixture"}}}
	digest, _ := messageSubmitDigest(session, payload)
	writeWireFrame(t, phone, map[string]any{"v": 1, "type": "message.submit", "request_id": request, "runtime_id": runtime, "session_id": session, "payload": payload})
	if readEnvelope(t, host).Type != "message.submit" || readEnvelope(t, phone).Payload["state"] != "received" {
		t.Fatal("fixture command was not admitted")
	}
	writeEnvelope(t, broken, "unsupported.fixture", map[string]any{})
	if frame := readEnvelope(t, broken); frame.Type != "error" || frame.Payload["code"] != "protocol.unsupported" {
		t.Fatal("protocol violation was not reported")
	}
	// Do not read again: this peer deliberately withholds the close response.
	until := time.Now().Add(500 * time.Millisecond)
	for len(relay.devicesForRuntime(runtime, ticket.DeviceID)) != 1 && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if len(relay.devicesForRuntime(runtime, ticket.DeviceID)) != 1 {
		t.Fatal("closing peer remains eligible for receipt delivery")
	}
	writeWireFrame(t, host, map[string]any{"v": 1, "type": "command.receipt", "request_id": request, "runtime_id": runtime, "runtime_epoch": epoch, "session_id": session, "device_id": ticket.DeviceID,
		"payload": map[string]any{"state": "host_accepted", "payload_sha256": digest}})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, raw, err := phone.Read(ctx)
	var receipt wireEnvelope
	var state map[string]any
	if err != nil || json.Unmarshal(raw, &receipt) != nil || json.Unmarshal(receipt.Payload, &state) != nil || receipt.Type != "command.receipt" || receipt.RequestID != request || state["state"] != "host_accepted" || state["payload_sha256"] != digest {
		t.Fatalf("another device socket waited for the close handshake: %v", err)
	}
	until = time.Now().Add(time.Second)
	remaining := 3
	for time.Now().Before(until) {
		relay.mu.Lock()
		remaining = len(relay.connections)
		relay.mu.Unlock()
		if remaining == 2 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if remaining != 2 {
		t.Fatal("unresponsive closing transport was not released within its grace period")
	}
}
