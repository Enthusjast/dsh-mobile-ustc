package relay

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/store"
)

func TestModelSelectionRequiresCapabilityScopeAndCurrentEpochAndNeverReplaysSettled(t *testing.T) {
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
					Scope: store.GrantScope{Actions: []string{"session.model.select"}, Sessions: []string{sessionID}, Workspaces: []string{}}},
				hostCredential: store.HostCredentialIdentity{InstallationID: installationID, KeyVersion: 1, PublicJWK: jwk, KeyThumbprint: thumbprint, ExpiresAt: time.Now().Add(time.Minute)},
				detached:       make(chan store.RuntimeConnection, 1),
			}
			if scenario == "scope" {
				fake.ticket.Scope.Actions = []string{"message.submit"}
			}
			hostCaps, deviceCaps := []string{"command.relay.v1", "connection.heartbeat.v1", modelSelectionCapability}, []string{"command.relay.v1", "connection.heartbeat.v1", modelSelectionCapability}
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
			selection := map[string]any{"v": 1, "type": "session.model.select", "request_id": requestID, "runtime_id": runtimeID, "runtime_epoch": epoch, "session_id": sessionID, "payload": map[string]any{"provider": "fixture", "model": "fixture"}}
			writeWireFrame(t, device, selection)
			if scenario != "allowed" {
				want := "protocol.unsupported"
				if scenario == "scope" {
					want = "access.denied"
				}
				if frame := readEnvelope(t, device); frame.Type != "error" || frame.Payload["code"] != want {
					t.Fatalf("unauthorized selection=%+v, want %s", frame, want)
				}
			} else {
				forwarded := readEnvelope(t, host)
				digest, err := modelSelectionDigest(sessionID, epoch, modelSelectionPayload{Provider: "fixture", Model: "fixture"})
				if err != nil {
					t.Fatal(err)
				}
				if forwarded.Type != "session.model.select" || forwarded.RuntimeEpoch != epoch || forwarded.PayloadSHA256 != digest || forwarded.UserID != fake.ticket.UserID || forwarded.DeviceID != fake.ticket.DeviceID {
					t.Fatalf("selection lost binding: %+v", forwarded)
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
				writeWireFrame(t, device, selection)
				if frame := readEnvelope(t, device); frame.Type != "command.receipt" || frame.Payload["state"] != "settled" {
					t.Fatalf("retry=%+v", frame)
				}
				selection["request_id"] = "77777777-7777-4777-8777-777777777777"
				selection["runtime_epoch"] = "88888888-8888-4888-8888-888888888888"
				writeWireFrame(t, device, selection)
				if frame := readEnvelope(t, device); frame.Type != "error" || frame.Payload["code"] != "runtime.changed" {
					t.Fatalf("stale epoch selection=%+v", frame)
				}
				selection["runtime_epoch"] = epoch
				selection["payload"] = map[string]any{"all": true}
				writeWireFrame(t, device, selection)
				if frame := readEnvelope(t, device); frame.Type != "error" || frame.Payload["code"] != "protocol.invalid" {
					t.Fatalf("invalid payload selection=%+v", frame)
				}
				selection["payload"] = map[string]any{"provider": "fixture", "model": "fixture"}
				selection["session_id"] = "99999999-9999-4999-8999-999999999999"
				writeWireFrame(t, device, selection)
				if frame := readEnvelope(t, device); frame.Type != "error" || frame.Payload["code"] != "access.denied" {
					t.Fatalf("out-of-scope selection=%+v", frame)
				}
			}
			// No rejected or settled-retry frame should reach the host. Reading
			// its next heartbeat also proves it remains connected.
			writeEnvelope(t, host, "ping", map[string]any{})
			if frame := readEnvelope(t, host); frame.Type != "pong" {
				t.Fatalf("selection was forwarded again or without authorization: %+v", frame)
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

func TestModelSelectionPayloadMatchesGoldenAndRejectsUnboundedOrPrivateFields(t *testing.T) {
	raw, err := os.ReadFile("../../../../contracts/ws/v1/golden/session-model-select.forwarded.json")
	if err != nil {
		t.Fatal(err)
	}
	frame, err := decodeWireFrame(raw)
	if err != nil {
		t.Fatal(err)
	}
	var payload modelSelectionPayload
	if err := decodePayload(frame.Payload, &payload); err != nil || !validModelSelection(payload) {
		t.Fatal("golden payload invalid", err)
	}
	digest, err := modelSelectionDigest(frame.SessionID, frame.RuntimeEpoch, payload)
	if err != nil || digest != frame.PayloadSHA256 {
		t.Fatal("Go/TypeScript model selection digest mismatch", digest, err)
	}
	for _, body := range []string{`{"provider":"fixture","model":"fixture","reasoning_effort":null}`, `{"provider":"fixture","model":"fixture","reasoning_effort":""}`, `{"provider":"fixture","model":"fixture","api_key":"private"}`} {
		if err := decodePayload(json.RawMessage(body), &payload); err == nil {
			t.Fatal("private or ambiguous selection accepted")
		}
	}
	for _, invalid := range []modelSelectionPayload{{Provider: "fixture"}, {Model: "fixture"}, {Provider: strings.Repeat("a", 129), Model: "fixture"}, {Provider: "fixture", Model: strings.Repeat("😀", 65)}, {Provider: "fixture", Model: "fixture", ReasoningEffort: strings.Repeat("a", 65)}} {
		if validModelSelection(invalid) {
			t.Fatal("unbounded or empty selection accepted")
		}
	}
}
