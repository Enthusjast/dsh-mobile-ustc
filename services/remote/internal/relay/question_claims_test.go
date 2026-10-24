package relay

import (
	"net/http/httptest"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/store"
)

func TestTimedQuestionClaimsAreScopedCorrelatedBoundedAndReleased(t *testing.T) {
	for _, scenario := range []string{"release", "revoked", "database", "unsubscribe", "disconnect", "read-only", "legacy", "legacy-host"} {
		t.Run(scenario, func(t *testing.T) {
			key := relayTestKey(t)
			jwk, thumbprint := relayTestPublicJWK(t, key)
			const installation = "11111111-1111-4111-8111-111111111111"
			const runtime = "33333333-3333-4333-8333-333333333333"
			const epoch = "44444444-4444-4444-8444-444444444444"
			const session = "55555555-5555-4555-8555-555555555555"
			const request = "66666666-6666-4666-8666-666666666666"
			const syncID = "77777777-7777-4777-8777-777777777777"
			const question = "99999999-9999-4999-8999-999999999999"
			ticket := store.TicketRedemption{UserID: installation, DeviceID: "22222222-2222-4222-8222-222222222222", RuntimeID: runtime, GrantVersion: 1, DeviceKeyVersion: 1, ProofPublicJWK: jwk, ProofKeyThumbprint: thumbprint, ExpiresAt: time.Now().Add(time.Minute),
				Scope: store.GrantScope{Actions: []string{"session.read", "question.answer"}, Workspaces: []string{}, Sessions: []string{session}}}
			if scenario == "read-only" {
				ticket.Scope.Actions = []string{"session.read"}
			}
			fake := &relayTestStore{ticket: ticket, hostCredential: store.HostCredentialIdentity{InstallationID: installation, KeyVersion: 1, PublicJWK: jwk, KeyThumbprint: thumbprint, ExpiresAt: time.Now().Add(time.Minute)}, detached: make(chan store.RuntimeConnection, 1)}
			relayServer := New(fake)
			server := httptest.NewServer(relayServer)
			t.Cleanup(server.Close)
			hostCaps := []string{}
			if scenario == "legacy-host" {
				hostCaps = []string{"command.relay.v1", "connection.heartbeat.v1", "session.read.v1"}
			}
			host := dialRelayHost(t, server.URL, key, installation, runtime, epoch, hostCaps...)
			defer host.CloseNow()
			caps := []string{}
			if scenario == "legacy" {
				caps = []string{"command.relay.v1", "connection.heartbeat.v1", "session.read.v1"}
			}
			device := dialRelayDevice(t, server.URL, key, ticket, runtime, caps...)
			defer device.CloseNow()
			other := dialRelayDevice(t, server.URL, key, ticket, runtime)
			defer other.CloseNow()
			writeWireFrame(t, device, map[string]any{"v": 1, "type": "session.subscribe", "request_id": request, "runtime_id": runtime, "session_id": session, "payload": map[string]any{}})
			ack := readEnvelope(t, device)
			forwarded := readEnvelope(t, host)
			if (forwarded.Payload["timed_questions"] == true) != (scenario != "legacy" && scenario != "legacy-host") {
				t.Fatalf("negotiation=%+v", forwarded)
			}
			writeWireFrame(t, host, map[string]any{"v": 1, "type": "session.snapshot", "request_id": request, "runtime_id": runtime, "runtime_epoch": epoch, "session_id": session,
				"subscription_id": ack.SubscriptionID, "sync_id": syncID, "payload": map[string]any{"cursor": 3, "records": []any{}, "has_more": false, "assistant": nil}})
			if frame := readEnvelope(t, device); frame.Type != "session.snapshot" {
				t.Fatal(frame)
			}
			claimID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
			claim := map[string]any{"v": 1, "type": "question.claim", "request_id": claimID, "runtime_id": runtime, "runtime_epoch": epoch, "session_id": session,
				"subscription_id": ack.SubscriptionID, "sync_id": syncID, "payload": map[string]any{"question_id": question}}
			writeWireFrame(t, other, claim)
			if frame := readEnvelope(t, other); frame.Type != "error" || frame.Payload["code"] != "protocol.resync_required" {
				t.Fatalf("foreign claim=%+v", frame)
			}
			if scenario == "release" {
				claim["payload"] = map[string]any{"question_id": question, "claim_id": ""}
				writeWireFrame(t, device, claim)
				if frame := readEnvelope(t, device); frame.Type != "error" || frame.Payload["code"] != "protocol.invalid" {
					t.Fatalf("extra release field forwarded on claim: %+v", frame)
				}
				claim["payload"] = map[string]any{"question_id": question}
			}
			writeWireFrame(t, device, claim)
			if scenario == "read-only" || scenario == "legacy" || scenario == "legacy-host" {
				want := "access.denied"
				if scenario == "legacy" || scenario == "legacy-host" {
					want = "protocol.unsupported"
				}
				if frame := readEnvelope(t, device); frame.Type != "error" || frame.Payload["code"] != want {
					t.Fatalf("claim denial=%+v", frame)
				}
				writeEnvelope(t, host, "ping", map[string]any{})
				if frame := readEnvelope(t, host); frame.Type != "pong" {
					t.Fatalf("denied claim reached host: %+v", frame)
				}
				return
			}
			if frame := readEnvelope(t, host); frame.Type != "question.claim" || frame.RequestID != claimID || frame.SyncID != syncID {
				t.Fatalf("claim forwarding=%+v", frame)
			}
			result := map[string]any{"v": 1, "type": "question.claimed", "request_id": claimID, "runtime_id": runtime, "runtime_epoch": epoch, "session_id": session,
				"subscription_id": ack.SubscriptionID, "sync_id": syncID, "payload": map[string]any{"question_id": question, "remaining_ms": 1000, "expires_at": time.Now().Add(time.Second)}}
			if scenario == "revoked" || scenario == "database" {
				fake.mu.Lock()
				fake.readErr = store.ErrAccessDenied
				if scenario == "database" {
					fake.readErr = store.ErrDatabaseUnavailable
				}
				fake.mu.Unlock()
				writeWireFrame(t, host, result)
				want := "access.denied"
				if scenario == "database" {
					want = "internal"
				}
				if frame := readEnvelope(t, device); frame.Type != "session.error" || frame.Payload["code"] != want {
					t.Fatalf("invalidated claim delivered timing data: %+v", frame)
				}
				if frame := readEnvelope(t, host); frame.Type != "session.unsubscribe" {
					t.Fatalf("invalidated native claim stayed alive: %+v", frame)
				}
				return
			}
			writeWireFrame(t, host, result)
			if frame := readEnvelope(t, device); frame.Type != "question.claimed" || frame.RequestID != claimID {
				t.Fatalf("claim result=%+v", frame)
			}
			if scenario == "release" {
				claim["type"], claim["payload"] = "question.release", map[string]any{"claim_id": claimID, "question_id": nil}
				writeWireFrame(t, device, claim)
				if frame := readEnvelope(t, device); frame.Type != "error" || frame.Payload["code"] != "protocol.invalid" {
					t.Fatalf("extra null field forwarded on release: %+v", frame)
				}
				claim["type"], claim["request_id"], claim["payload"] = "question.release", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", map[string]any{"claim_id": claimID}
				writeWireFrame(t, device, claim)
				if frame := readEnvelope(t, host); frame.Type != "question.release" {
					t.Fatalf("release=%+v", frame)
				}
				if frame := readEnvelope(t, device); frame.Type != "question.released" {
					t.Fatalf("release ack=%+v", frame)
				}
				result["type"], result["payload"] = "question.claim.closed", map[string]any{"question_id": question, "code": "question.ended"}
				writeWireFrame(t, host, result)
				claim["type"], claim["request_id"], claim["payload"] = "question.claim", claimID, map[string]any{"question_id": question}
				writeWireFrame(t, device, claim)
				if frame := readEnvelope(t, device); frame.Type != "error" || frame.Payload["code"] != "rate.limited" {
					t.Fatalf("retired claim reused or late close leaked: %+v", frame)
				}
				for range 4 {
					id, err := randomUUID()
					if err != nil {
						t.Fatal(err)
					}
					claim["request_id"] = id
					writeWireFrame(t, device, claim)
					if frame := readEnvelope(t, host); frame.Type != "question.claim" || frame.RequestID != id {
						t.Fatalf("bounded claim admission=%+v", frame)
					}
				}
				id, err := randomUUID()
				if err != nil {
					t.Fatal(err)
				}
				claim["request_id"] = id
				writeWireFrame(t, device, claim)
				if frame := readEnvelope(t, device); frame.Type != "error" || frame.Payload["code"] != "rate.limited" {
					t.Fatalf("fifth active claim admitted: %+v", frame)
				}
			} else if scenario == "unsubscribe" {
				claim["type"], claim["payload"] = "session.unsubscribe", map[string]any{}
				delete(claim, "sync_id")
				writeWireFrame(t, device, claim)
				if frame := readEnvelope(t, host); frame.Type != "session.unsubscribe" {
					t.Fatalf("unsubscribe=%+v", frame)
				}
				if frame := readEnvelope(t, device); frame.Type != "session.unsubscribed" {
					t.Fatalf("unsubscribe ack=%+v", frame)
				}
			} else {
				_ = device.CloseNow()
				if frame := readEnvelope(t, host); frame.Type != "session.unsubscribe" {
					t.Fatalf("disconnect left native claim: %+v", frame)
				}
			}
			writeEnvelope(t, other, "ping", map[string]any{})
			if frame := readEnvelope(t, other); frame.Type != "pong" {
				t.Fatalf("claim result leaked to sibling socket: %+v", frame)
			}
		})
	}
}
