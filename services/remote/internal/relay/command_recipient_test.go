package relay

import (
	"net/http/httptest"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/store"
)

func TestCommandReceiptsStayWithinEachSocketScopeForTheSameDevice(t *testing.T) {
	key := relayTestKey(t)
	jwk, thumbprint := relayTestPublicJWK(t, key)
	const installationID = "11111111-1111-4111-8111-111111111111"
	const runtimeID = "33333333-3333-4333-8333-333333333333"
	const epoch = "44444444-4444-4444-8444-444444444444"
	const sessionID = "55555555-5555-4555-8555-555555555555"
	const requestID = "66666666-6666-4666-8666-666666666666"
	ticket := store.TicketRedemption{UserID: installationID, DeviceID: "22222222-2222-4222-8222-222222222222", RuntimeID: runtimeID, GrantVersion: 1, DeviceKeyVersion: 1,
		ProofPublicJWK: jwk, ProofKeyThumbprint: thumbprint, ExpiresAt: time.Now().Add(time.Minute), Scope: store.GrantScope{Actions: []string{"message.submit"}, Sessions: []string{sessionID}, Workspaces: []string{}}}
	fake := &relayTestStore{ticket: ticket, hostCredential: store.HostCredentialIdentity{InstallationID: installationID, KeyVersion: 1, PublicJWK: jwk, KeyThumbprint: thumbprint, ExpiresAt: time.Now().Add(time.Minute)}, detached: make(chan store.RuntimeConnection, 1)}
	server := httptest.NewServer(New(fake))
	t.Cleanup(server.Close)
	host := dialRelayHost(t, server.URL, key, installationID, runtimeID, epoch)
	defer host.CloseNow()
	device := dialRelayDevice(t, server.URL, key, ticket, runtimeID)
	defer device.CloseNow()
	narrow := ticket
	narrow.Scope.Sessions = []string{"77777777-7777-4777-8777-777777777777"}
	fake.mu.Lock()
	fake.ticket = narrow
	fake.mu.Unlock()
	other := dialRelayDevice(t, server.URL, key, narrow, runtimeID)
	defer other.CloseNow()
	payload := messageSubmitPayload{Mode: "queue", Content: []messageContent{{Type: "text", Text: "scoped receipt fixture"}}}
	digest, _ := messageSubmitDigest(sessionID, payload)
	writeWireFrame(t, device, map[string]any{"v": 1, "type": "message.submit", "request_id": requestID, "runtime_id": runtimeID, "session_id": sessionID, "payload": payload})
	if frame := readEnvelope(t, host); frame.Type != "message.submit" {
		t.Fatalf("submit=%+v", frame)
	}
	if frame := readEnvelope(t, device); frame.Type != "command.receipt" || frame.Payload["state"] != "received" {
		t.Fatalf("received=%+v", frame)
	}
	receipt := map[string]any{"v": 1, "type": "command.receipt", "request_id": requestID, "runtime_id": runtimeID, "runtime_epoch": epoch, "session_id": sessionID, "device_id": ticket.DeviceID,
		"payload": map[string]any{"state": "host_accepted", "payload_sha256": digest}}
	writeWireFrame(t, host, receipt)
	if frame := readEnvelope(t, device); frame.Type != "command.receipt" || frame.Payload["state"] != "host_accepted" {
		t.Fatalf("accepted=%+v", frame)
	}
	writeEnvelope(t, other, "ping", map[string]any{})
	if frame := readEnvelope(t, other); frame.Type != "pong" {
		t.Fatalf("out-of-scope receipt leaked: %+v", frame)
	}
	fake.mu.Lock()
	fake.leaseErr = store.ErrDatabaseUnavailable
	fake.mu.Unlock()
	receipt["payload"] = map[string]any{"state": "dispatching", "payload_sha256": digest}
	writeWireFrame(t, host, receipt)
	assertRevokedSocket(t, device, "internal")
	assertRevokedSocket(t, other, "internal")
}
