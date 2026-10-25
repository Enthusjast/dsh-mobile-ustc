package relay

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/store"
)

func TestSessionArchiveDigestMatchesSharedGolden(t *testing.T) {
	for _, name := range []string{"session-archive", "session-archive-stop", "session-restore"} {
		data, err := os.ReadFile("../../../../contracts/ws/v1/golden/" + name + ".forwarded.json")
		if err != nil {
			t.Fatal(err)
		}
		var frame struct {
			SessionID    string                `json:"session_id"`
			RuntimeEpoch string                `json:"runtime_epoch"`
			Digest       string                `json:"payload_sha256"`
			Payload      sessionArchivePayload `json:"payload"`
		}
		if err := json.Unmarshal(data, &frame); err != nil {
			t.Fatal(err)
		}
		if actual := sessionArchiveDigest(frame.SessionID, frame.RuntimeEpoch, frame.Payload); actual != frame.Digest {
			t.Fatalf("%s digest=%s want=%s", name, actual, frame.Digest)
		}
	}
}

func TestSessionArchiveRequiresNegotiationExplicitIntentScopeAndOriginalEpoch(t *testing.T) {
	const installationID = "11111111-1111-4111-8111-111111111111"
	const runtimeID = "33333333-3333-4333-8333-333333333333"
	const epoch = "44444444-4444-4444-8444-444444444444"
	const sessionID = "55555555-5555-4555-8555-555555555555"
	const requestID = "66666666-6666-4666-8666-666666666666"
	for _, scenario := range []string{"archive", "archive-stop", "restore", "scope", "device-capability", "host-capability", "epoch", "missing", "null", "restore-stop", "resource"} {
		t.Run(scenario, func(t *testing.T) {
			key := relayTestKey(t)
			jwk, thumbprint := relayTestPublicJWK(t, key)
			fake := &relayTestStore{
				ticket: store.TicketRedemption{UserID: installationID, DeviceID: "22222222-2222-4222-8222-222222222222", RuntimeID: runtimeID,
					DeviceKeyVersion: 1, GrantVersion: 1, ProofPublicJWK: jwk, ProofKeyThumbprint: thumbprint, ExpiresAt: time.Now().Add(time.Minute),
					Scope: store.GrantScope{Actions: []string{"session.archive"}, Sessions: []string{sessionID}, Workspaces: []string{}}},
				hostCredential: store.HostCredentialIdentity{InstallationID: installationID, KeyVersion: 1, PublicJWK: jwk, KeyThumbprint: thumbprint, ExpiresAt: time.Now().Add(time.Minute)},
				detached:       make(chan store.RuntimeConnection, 1),
			}
			caps := []string{"command.relay.v1", "connection.heartbeat.v1", "session.archive.v1"}
			hostCaps, deviceCaps := caps, caps
			payload := map[string]any{"archived": true, "stop_activity": false}
			want, targetEpoch := "", epoch
			switch scenario {
			case "archive-stop":
				payload["stop_activity"] = true
			case "restore":
				payload["archived"] = false
			case "scope":
				fake.ticket.Scope.Actions = []string{"message.submit"}
				want = "access.denied"
			case "device-capability":
				deviceCaps = caps[:2]
				want = "protocol.unsupported"
			case "host-capability":
				hostCaps = caps[:2]
				want = "protocol.unsupported"
			case "epoch":
				targetEpoch = installationID
				want = "runtime.changed"
			case "missing":
				delete(payload, "stop_activity")
				want = "protocol.invalid"
			case "null":
				payload["archived"] = nil
				want = "protocol.invalid"
			case "restore-stop":
				payload["archived"], payload["stop_activity"] = false, true
				want = "protocol.invalid"
			case "resource":
				fake.ticket.Scope.Sessions = []string{}
				want = "access.denied"
			}
			server := httptest.NewServer(New(fake))
			t.Cleanup(server.Close)
			host := dialRelayHost(t, server.URL, key, installationID, runtimeID, epoch, hostCaps...)
			defer host.CloseNow()
			device := dialRelayDevice(t, server.URL, key, fake.ticket, runtimeID, deviceCaps...)
			defer device.CloseNow()
			command := map[string]any{"v": 1, "type": "session.archive", "request_id": requestID, "runtime_id": runtimeID, "runtime_epoch": targetEpoch, "session_id": sessionID, "payload": payload}
			writeWireFrame(t, device, command)
			if want != "" {
				if frame := readEnvelope(t, device); frame.Type != "error" || frame.Payload["code"] != want {
					t.Fatalf("archive error=%+v want=%s", frame, want)
				}
			} else {
				forward := readEnvelope(t, host)
				archived, stop := payload["archived"].(bool), payload["stop_activity"].(bool)
				digest := sessionArchiveDigest(sessionID, epoch, sessionArchivePayload{Archived: &archived, StopActivity: &stop})
				if forward.Type != "session.archive" || forward.RuntimeEpoch != epoch || forward.PayloadSHA256 != digest || forward.UserID != fake.ticket.UserID || forward.DeviceID != fake.ticket.DeviceID {
					t.Fatalf("archive lost binding=%+v", forward)
				}
				if frame := readEnvelope(t, device); frame.Payload["state"] != "received" {
					t.Fatalf("received=%+v", frame)
				}
				for _, state := range []string{"host_accepted", "dispatching", "settled"} {
					writeWireFrame(t, host, map[string]any{"v": 1, "type": "command.receipt", "request_id": requestID, "runtime_id": runtimeID, "runtime_epoch": epoch, "session_id": sessionID, "device_id": fake.ticket.DeviceID, "payload": map[string]any{"state": state, "payload_sha256": digest}})
					if frame := readEnvelope(t, device); frame.Type != "command.receipt" || frame.Payload["state"] != state {
						t.Fatalf("receipt=%+v want=%s", frame, state)
					}
				}
				writeWireFrame(t, device, command)
				if frame := readEnvelope(t, device); frame.Payload["state"] != "settled" {
					t.Fatalf("retry=%+v", frame)
				}
				payload["archived"], payload["stop_activity"] = !archived, false
				writeWireFrame(t, device, command)
				if frame := readEnvelope(t, device); frame.Type != "error" || frame.Payload["code"] != "command.request_conflict" {
					t.Fatalf("conflicting desired state=%+v", frame)
				}
			}
			writeEnvelope(t, host, "ping", map[string]any{})
			if frame := readEnvelope(t, host); frame.Type != "pong" {
				t.Fatalf("unauthorized or settled retry reached host=%+v", frame)
			}
		})
	}
}
