package relay

import (
	"net/http/httptest"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/store"
	"github.com/coder/websocket"
)

func TestSessionCreationRequiresWorkspaceScopeAndNegotiationAndRoutesOnlyBoundReceipts(t *testing.T) {
	const installationID = "11111111-1111-4111-8111-111111111111"
	const runtimeID = "33333333-3333-4333-8333-333333333333"
	const epoch = "44444444-4444-4444-8444-444444444444"
	const requestID = "66666666-6666-4666-8666-666666666666"
	const workspaceID = "88888888-8888-4888-8888-888888888888"
	for _, scenario := range []string{"allowed", "action", "workspace", "device-capability", "host-capability"} {
		t.Run(scenario, func(t *testing.T) {
			key := relayTestKey(t)
			jwk, thumbprint := relayTestPublicJWK(t, key)
			ticket := store.TicketRedemption{UserID: installationID, DeviceID: "22222222-2222-4222-8222-222222222222", RuntimeID: runtimeID, GrantVersion: 1, DeviceKeyVersion: 1,
				ProofPublicJWK: jwk, ProofKeyThumbprint: thumbprint, ExpiresAt: time.Now().Add(time.Minute), Scope: store.GrantScope{Actions: []string{"session.create"}, Workspaces: []string{workspaceID}, Sessions: []string{}}}
			if scenario == "action" {
				ticket.Scope.Actions = []string{"message.submit"}
			}
			if scenario == "workspace" {
				ticket.Scope.Workspaces = []string{}
				ticket.Scope.Sessions = []string{installationID}
			}
			fake := &relayTestStore{ticket: ticket, hostCredential: store.HostCredentialIdentity{InstallationID: installationID, KeyVersion: 1, PublicJWK: jwk, KeyThumbprint: thumbprint, ExpiresAt: time.Now().Add(time.Minute)}, detached: make(chan store.RuntimeConnection, 1)}
			server := httptest.NewServer(New(fake))
			t.Cleanup(server.Close)
			legacyCaps := []string{"command.relay.v1", "connection.heartbeat.v1"}
			hostCaps, deviceCaps := []string{}, []string{}
			if scenario == "host-capability" {
				hostCaps = legacyCaps
			}
			if scenario == "device-capability" {
				deviceCaps = legacyCaps
			}
			host := dialRelayHost(t, server.URL, key, installationID, runtimeID, epoch, hostCaps...)
			defer host.CloseNow()
			device := dialRelayDevice(t, server.URL, key, ticket, runtimeID, deviceCaps...)
			defer device.CloseNow()
			request := map[string]any{"v": 1, "type": "session.create", "request_id": requestID, "runtime_id": runtimeID, "runtime_epoch": epoch, "payload": map[string]any{"workspace_id": workspaceID, "preset": "standard"}}
			writeWireFrame(t, device, request)
			if scenario != "allowed" {
				want := "access.denied"
				if scenario == "device-capability" || scenario == "host-capability" {
					want = "protocol.unsupported"
				}
				if frame := readEnvelope(t, device); frame.Type != "error" || frame.Payload["code"] != want {
					t.Fatalf("creation denial=%+v, want %s", frame, want)
				}
			} else {
				forwarded := readEnvelope(t, host)
				const digest = "7d5f10077d2c18e4aaa2049a06eb146f732ab05c88093d64bcc0ec08cf326da7"
				if forwarded.Type != "session.create" || forwarded.SessionID != "" || forwarded.RuntimeEpoch != epoch || forwarded.PayloadSHA256 != digest || forwarded.UserID != ticket.UserID || forwarded.DeviceID != ticket.DeviceID {
					t.Fatalf("creation lost binding: %+v", forwarded)
				}
				if frame := readEnvelope(t, device); frame.Type != "command.receipt" || frame.SessionID != "" || frame.Payload["workspace_id"] != workspaceID || frame.Payload["state"] != "received" {
					t.Fatalf("pending receipt=%+v", frame)
				}
				// The same device can have a narrower ticket, or an older protocol
				// socket. Neither may receive this creation's metadata.
				narrow := ticket
				narrow.Scope = store.GrantScope{Actions: []string{"message.submit"}, Workspaces: []string{}, Sessions: []string{installationID}}
				fake.mu.Lock()
				fake.ticket = narrow
				fake.mu.Unlock()
				narrowSocket := dialRelayDevice(t, server.URL, key, narrow, runtimeID)
				defer narrowSocket.CloseNow()
				fake.mu.Lock()
				fake.ticket = ticket
				fake.mu.Unlock()
				legacy := dialRelayDevice(t, server.URL, key, ticket, runtimeID, legacyCaps...)
				defer legacy.CloseNow()
				sessionID, err := store.MobileSessionID(runtimeID, "native:created-session")
				if err != nil {
					t.Fatal(err)
				}
				for _, state := range []string{"host_accepted", "dispatching", "settled"} {
					payload := map[string]any{"state": state, "payload_sha256": digest, "workspace_id": workspaceID}
					receipt := map[string]any{"v": 1, "type": "command.receipt", "request_id": requestID, "runtime_id": runtimeID, "runtime_epoch": epoch, "device_id": ticket.DeviceID, "payload": payload}
					if state == "settled" {
						receipt["session_id"] = sessionID
						payload["created_session"] = store.SessionCatalogItem{SessionID: sessionID, DSHSessionID: "native:created-session", WorkspaceID: ptr(workspaceID), State: "available", LastPersistedSeq: 3}
					}
					writeWireFrame(t, host, receipt)
					if frame := readEnvelope(t, device); frame.Type != "command.receipt" || frame.Payload["state"] != state || (state == "settled" && frame.SessionID != sessionID) {
						t.Fatalf("creation receipt=%+v, want %s", frame, state)
					}
				}
				writeWireFrame(t, device, request)
				if frame := readEnvelope(t, device); frame.Type != "command.receipt" || frame.Payload["state"] != "settled" || frame.SessionID != sessionID {
					t.Fatalf("settled retry=%+v", frame)
				}
				for _, peer := range []*websocket.Conn{narrowSocket, legacy} {
					writeEnvelope(t, peer, "ping", map[string]any{})
					if frame := readEnvelope(t, peer); frame.Type != "pong" {
						t.Fatalf("creation leaked to unrelated ticket/capabilities: %+v", frame)
					}
				}
				request["runtime_epoch"] = installationID
				writeWireFrame(t, device, request)
				if frame := readEnvelope(t, device); frame.Type != "error" || frame.Payload["code"] != "runtime.changed" {
					t.Fatalf("stale creation=%+v", frame)
				}
				request["runtime_epoch"] = epoch
				request["payload"] = map[string]any{"workspace_id": workspaceID, "preset": "changed"}
				writeWireFrame(t, device, request)
				if frame := readEnvelope(t, device); frame.Type != "error" || frame.Payload["code"] != "command.request_conflict" {
					t.Fatalf("changed creation=%+v", frame)
				}
			}
			writeEnvelope(t, host, "ping", map[string]any{})
			if frame := readEnvelope(t, host); frame.Type != "pong" {
				t.Fatalf("rejected or settled creation was forwarded: %+v", frame)
			}
		})
	}
}

func ptr(value string) *string { return &value }
