package relay

import (
	"net/http/httptest"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/store"
)

func TestSessionCancelRequiresCapabilityScopeAndCurrentEpochAndNeverReplaysSettled(t *testing.T) {
	const installationID = "11111111-1111-4111-8111-111111111111"
	const runtimeID = "33333333-3333-4333-8333-333333333333"
	const epoch = "44444444-4444-4444-8444-444444444444"
	const sessionID = "55555555-5555-4555-8555-555555555555"
	const requestID = "66666666-6666-4666-8666-666666666666"
	for _, scenario := range []string{"allowed", "scope", "device-capability", "host-capability"} {
		t.Run(scenario, func(t *testing.T) {
			key := relayTestKey(t)
			jwk, thumbprint := relayTestPublicJWK(t, key)
			fake := &relayTestStore{
				ticket: store.TicketRedemption{UserID: installationID, DeviceID: "22222222-2222-4222-8222-222222222222", RuntimeID: runtimeID,
					DeviceKeyVersion: 1, GrantVersion: 1, ProofPublicJWK: jwk, ProofKeyThumbprint: thumbprint, ExpiresAt: time.Now().Add(time.Minute),
					Scope: store.GrantScope{Actions: []string{"session.cancel"}, Sessions: []string{sessionID}, Workspaces: []string{}}},
				hostCredential: store.HostCredentialIdentity{InstallationID: installationID, KeyVersion: 1, PublicJWK: jwk, KeyThumbprint: thumbprint, ExpiresAt: time.Now().Add(time.Minute)},
				detached:       make(chan store.RuntimeConnection, 1),
			}
			if scenario == "scope" {
				fake.ticket.Scope.Actions = []string{"message.submit"}
			}
			hostCaps, deviceCaps := []string{}, []string{}
			if scenario == "device-capability" {
				deviceCaps = []string{"command.relay.v1", "connection.heartbeat.v1"}
			}
			if scenario == "host-capability" {
				hostCaps = []string{"command.relay.v1", "connection.heartbeat.v1"}
			}
			relayServer := New(fake)
			server := httptest.NewServer(relayServer)
			t.Cleanup(server.Close)
			host := dialRelayHost(t, server.URL, key, installationID, runtimeID, epoch, hostCaps...)
			defer host.CloseNow()
			device := dialRelayDevice(t, server.URL, key, fake.ticket, runtimeID, deviceCaps...)
			defer device.CloseNow()
			cancel := map[string]any{"v": 1, "type": "session.cancel", "request_id": requestID, "runtime_id": runtimeID, "runtime_epoch": epoch, "session_id": sessionID, "payload": map[string]any{}}
			writeWireFrame(t, device, cancel)
			if scenario != "allowed" {
				want := "protocol.unsupported"
				if scenario == "scope" {
					want = "access.denied"
				}
				if frame := readEnvelope(t, device); frame.Type != "error" || frame.Payload["code"] != want {
					t.Fatalf("unauthorized cancel=%+v, want %s", frame, want)
				}
			} else {
				forwarded := readEnvelope(t, host)
				const digest = "ec3125acb8c48bc2f6f4d6bd491f439521caeb83726a494b56da7d772da28c2b"
				if forwarded.Type != "session.cancel" || forwarded.RuntimeEpoch != epoch || forwarded.PayloadSHA256 != digest || forwarded.UserID != fake.ticket.UserID || forwarded.DeviceID != fake.ticket.DeviceID {
					t.Fatalf("cancel lost binding: %+v", forwarded)
				}
				if frame := readEnvelope(t, device); frame.Type != "command.receipt" || frame.Payload["state"] != "received" {
					t.Fatalf("received=%+v", frame)
				}
				for _, state := range []string{"host_accepted", "dispatching", "settled"} {
					writeWireFrame(t, host, map[string]any{"v": 1, "type": "command.receipt", "request_id": requestID, "runtime_id": runtimeID, "runtime_epoch": epoch, "session_id": sessionID, "device_id": fake.ticket.DeviceID, "payload": map[string]any{"state": state, "payload_sha256": digest}})
					if frame := readEnvelope(t, device); frame.Type != "command.receipt" || frame.Payload["state"] != state {
						t.Fatalf("receipt=%+v, want %s", frame, state)
					}
				}
				writeWireFrame(t, device, cancel)
				if frame := readEnvelope(t, device); frame.Type != "command.receipt" || frame.Payload["state"] != "settled" {
					t.Fatalf("retry=%+v", frame)
				}
				cancel["request_id"] = "77777777-7777-4777-8777-777777777777"
				cancel["runtime_epoch"] = "88888888-8888-4888-8888-888888888888"
				writeWireFrame(t, device, cancel)
				if frame := readEnvelope(t, device); frame.Type != "error" || frame.Payload["code"] != "runtime.changed" {
					t.Fatalf("stale epoch cancel=%+v", frame)
				}
				cancel["runtime_epoch"] = epoch
				cancel["payload"] = map[string]any{"all": true}
				writeWireFrame(t, device, cancel)
				if frame := readEnvelope(t, device); frame.Type != "error" || frame.Payload["code"] != "protocol.invalid" {
					t.Fatalf("invalid payload cancel=%+v", frame)
				}
				cancel["payload"] = map[string]any{}
				cancel["session_id"] = "99999999-9999-4999-8999-999999999999"
				writeWireFrame(t, device, cancel)
				if frame := readEnvelope(t, device); frame.Type != "error" || frame.Payload["code"] != "access.denied" {
					t.Fatalf("out-of-scope cancel=%+v", frame)
				}
			}
			// No rejected or settled-retry frame should reach the host. Reading
			// its next heartbeat also proves it remains connected.
			writeEnvelope(t, host, "ping", map[string]any{})
			if frame := readEnvelope(t, host); frame.Type != "pong" {
				t.Fatalf("cancel was forwarded again or without authorization: %+v", frame)
			}
			fake.mu.Lock()
			count := len(fake.commands)
			fake.mu.Unlock()
			want := 0
			if scenario == "allowed" {
				want = 1
			}
			if count != want {
				t.Fatalf("stored %d commands, want %d", count, want)
			}
		})
	}
}
