package relay

import (
	"dsh-mobile-ustc/services/remote/internal/store"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCreationOptionsAreScopedEphemeralMetadataNotCommands(t *testing.T) {
	const installation = "11111111-1111-4111-8111-111111111111"
	const runtime = "33333333-3333-4333-8333-333333333333"
	const epoch = "44444444-4444-4444-8444-444444444444"
	const request = "66666666-6666-4666-8666-666666666666"
	const workspace = "88888888-8888-4888-8888-888888888888"
	const other = "99999999-9999-4999-8999-999999999999"
	for _, scenario := range []string{"allowed", "no-create-action", "session-only", "device-capability", "host-capability", "budget"} {
		t.Run(scenario, func(t *testing.T) {
			key := relayTestKey(t)
			jwk, jkt := relayTestPublicJWK(t, key)
			ticket := store.TicketRedemption{UserID: installation, DeviceID: "22222222-2222-4222-8222-222222222222", RuntimeID: runtime, GrantVersion: 1, DeviceKeyVersion: 1, ProofPublicJWK: jwk, ProofKeyThumbprint: jkt, ExpiresAt: time.Now().Add(time.Minute), Scope: store.GrantScope{Actions: []string{"session.create", "command.status"}, Workspaces: []string{workspace}, Sessions: []string{}}}
			if scenario == "no-create-action" {
				ticket.Scope.Actions = []string{"command.status"}
			}
			if scenario == "session-only" {
				ticket.Scope.Workspaces = []string{}
				ticket.Scope.Sessions = []string{other}
			}
			fake := &relayTestStore{ticket: ticket, hostCredential: store.HostCredentialIdentity{InstallationID: installation, KeyVersion: 1, PublicJWK: jwk, KeyThumbprint: jkt, ExpiresAt: time.Now().Add(time.Minute)}, detached: make(chan store.RuntimeConnection, 1)}
			relay := New(fake)
			server := httptest.NewServer(relay)
			defer server.Close()
			caps := []string{"connection.heartbeat.v1", "command.relay.v1", "session.create.v1", creationOptionsCapability}
			hostCaps := append([]string{}, caps...)
			deviceCaps := append([]string{}, caps...)
			if scenario == "device-capability" {
				deviceCaps = []string{"connection.heartbeat.v1", "command.relay.v1", "session.create.v1"}
			}
			if scenario == "host-capability" {
				hostCaps = []string{"connection.heartbeat.v1", "command.relay.v1", "session.create.v1"}
			}
			host := dialRelayHost(t, server.URL, key, installation, runtime, epoch, hostCaps...)
			defer host.CloseNow()
			if scenario == "budget" {
				relay.mu.Lock()
				relay.creationOptionsBytes = maxCreationOptionsBytes
				relay.mu.Unlock()
			}
			writeWireFrame(t, host, map[string]any{"v": 1, "type": "session.create.options", "request_id": request, "runtime_id": runtime, "runtime_epoch": epoch, "payload": sessionCreationOptions{Workspaces: []creationWorkspace{{ID: workspace, Label: "授权项目"}, {ID: other, Label: "另一个项目"}}, Presets: []string{"standard", "review"}}})
			published := readEnvelope(t, host)
			if scenario == "host-capability" || scenario == "budget" {
				want := "protocol.unsupported"
				if scenario == "budget" {
					want = "rate.limited"
				}
				if published.Type != "error" || published.Payload["code"] != want {
					t.Fatalf("metadata publication denial=%+v", published)
				}
			} else if published.Type != "session.create.options.ack" || published.Payload["workspace_count"] != float64(2) {
				t.Fatalf("metadata acknowledgement=%+v", published)
			}
			device := dialRelayDevice(t, server.URL, key, ticket, runtime, deviceCaps...)
			defer device.CloseNow()
			writeWireFrame(t, device, map[string]any{"v": 1, "type": "session.create.options.get", "request_id": request, "runtime_id": runtime, "payload": map[string]any{}})
			result := readEnvelope(t, device)
			if scenario != "allowed" {
				want := "access.denied"
				if strings.Contains(scenario, "capability") {
					want = "protocol.unsupported"
				}
				if scenario == "budget" {
					want = "runtime.offline"
				}
				if result.Type != "error" || result.Payload["code"] != want {
					t.Fatalf("options denial=%+v want=%s", result, want)
				}
			} else {
				workspaces := result.Payload["workspaces"].([]any)
				if result.Type != "session.create.options.result" || result.RuntimeEpoch != epoch || len(workspaces) != 1 || workspaces[0].(map[string]any)["workspace_id"] != workspace || len(result.Payload["presets"].([]any)) != 2 {
					t.Fatalf("metadata escaped literal workspace scope: %+v", result)
				}
			}
			fake.mu.Lock()
			count := len(fake.commands)
			fake.mu.Unlock()
			if count != 0 {
				t.Fatal("metadata query persisted a command")
			}
		})
	}
}

func TestCreationOptionsRejectAmbiguousAndOversizedPublicMetadata(t *testing.T) {
	const id = "88888888-8888-4888-8888-888888888888"
	valid := sessionCreationOptions{Workspaces: []creationWorkspace{{ID: id, Label: "项目🙂"}}, Presets: []string{"standard"}}
	if !validCreationOptions(valid) {
		t.Fatal("scalar Unicode label rejected")
	}
	for _, bad := range []sessionCreationOptions{
		{Workspaces: []creationWorkspace{{ID: id, Label: "bad\x00"}}, Presets: valid.Presets},
		{Workspaces: []creationWorkspace{{ID: id, Label: " "}}, Presets: valid.Presets},
		{Workspaces: []creationWorkspace{{ID: id, Label: strings.Repeat("中", 33)}}, Presets: valid.Presets},
		{Workspaces: []creationWorkspace{{ID: id, Label: "one"}, {ID: id, Label: "two"}}, Presets: valid.Presets},
		{Workspaces: valid.Workspaces, Presets: []string{"standard", "standard"}},
		{Workspaces: valid.Workspaces, Presets: []string{"../standard"}},
	} {
		if validCreationOptions(bad) {
			t.Fatal("unsafe public creation metadata accepted")
		}
	}
}
