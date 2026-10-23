package relay

import (
	"net/http/httptest"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/store"
)

func TestQuestionAnswerDigestMatchesUnicodeGoldenAndRejectsInvalidBatches(t *testing.T) {
	custom := "中文 < & \\ line\n"
	answer := questionAnswerPayload{QuestionID: "99999999-9999-4999-8999-999999999999", Answers: []questionAnswerItem{{ID: "plan", Selected: []string{"Continue"}, Custom: &custom}}}
	if !validQuestionAnswer(answer) {
		t.Fatal("valid batch rejected")
	}
	if digest := questionAnswerDigest("55555555-5555-4555-8555-555555555555", "44444444-4444-4444-8444-444444444444", answer); digest != "a1d12f0ecdb9e9d2c48ee8bbbf1554cc1349f5283dcc673db35036184f4934dc" {
		t.Fatalf("question digest=%s", digest)
	}
	for _, invalid := range []questionAnswerPayload{
		{QuestionID: answer.QuestionID, Answers: nil},
		{QuestionID: answer.QuestionID, Answers: []questionAnswerItem{{ID: "plan"}}},
		{QuestionID: answer.QuestionID, Answers: []questionAnswerItem{{ID: "plan", Selected: []string{"A", "A"}}}},
		{QuestionID: answer.QuestionID, Answers: []questionAnswerItem{{ID: "plan", Selected: []string{}}, {ID: "plan", Selected: []string{}}}},
	} {
		if validQuestionAnswer(invalid) {
			t.Fatalf("invalid answer batch accepted: %+v", invalid)
		}
	}
	var nullable questionAnswerPayload
	if err := decodePayload([]byte(`{"question_id":"99999999-9999-4999-8999-999999999999","answers":[{"id":"plan","selected":[],"custom":null}]}`), &nullable); err == nil {
		t.Fatal("null answer text was silently normalized")
	}
}

func TestQuestionSnapshotsAndAnswersRequireNegotiationScopeAndCurrentEpoch(t *testing.T) {
	const installationID = "11111111-1111-4111-8111-111111111111"
	const runtimeID = "33333333-3333-4333-8333-333333333333"
	const epoch = "44444444-4444-4444-8444-444444444444"
	const sessionID = "55555555-5555-4555-8555-555555555555"
	const requestID = "66666666-6666-4666-8666-666666666666"
	const questionID = "99999999-9999-4999-8999-999999999999"
	for _, scenario := range []string{"allowed", "missing-action", "missing-scope", "device-capability", "host-capability"} {
		t.Run(scenario, func(t *testing.T) {
			key := relayTestKey(t)
			jwk, thumbprint := relayTestPublicJWK(t, key)
			ticket := store.TicketRedemption{UserID: installationID, DeviceID: "22222222-2222-4222-8222-222222222222", RuntimeID: runtimeID, GrantVersion: 1, DeviceKeyVersion: 1,
				ProofPublicJWK: jwk, ProofKeyThumbprint: thumbprint, ExpiresAt: time.Now().Add(time.Minute), Scope: store.GrantScope{Actions: []string{"question.answer", "session.read"}, Workspaces: []string{}, Sessions: []string{sessionID}}}
			if scenario == "missing-action" {
				ticket.Scope.Actions = []string{"session.read"}
			}
			if scenario == "missing-scope" {
				ticket.Scope.Sessions = []string{}
			}
			fake := &relayTestStore{ticket: ticket, hostCredential: store.HostCredentialIdentity{InstallationID: installationID, KeyVersion: 1, PublicJWK: jwk, KeyThumbprint: thumbprint, ExpiresAt: time.Now().Add(time.Minute)}, detached: make(chan store.RuntimeConnection, 1)}
			hostCaps, deviceCaps := []string{}, []string{}
			legacy := []string{"command.relay.v1", "connection.heartbeat.v1", "session.read.v1"}
			if scenario == "host-capability" {
				hostCaps = legacy
			}
			if scenario == "device-capability" {
				deviceCaps = legacy
			}
			server := httptest.NewServer(New(fake))
			t.Cleanup(server.Close)
			host := dialRelayHost(t, server.URL, key, installationID, runtimeID, epoch, hostCaps...)
			defer host.CloseNow()
			device := dialRelayDevice(t, server.URL, key, ticket, runtimeID, deviceCaps...)
			defer device.CloseNow()
			answer := map[string]any{"v": 1, "type": "question.answer", "request_id": requestID, "runtime_id": runtimeID, "runtime_epoch": epoch, "session_id": sessionID,
				"payload": map[string]any{"question_id": questionID, "answers": []any{map[string]any{"id": "plan", "selected": []string{"Continue"}}}}}
			writeWireFrame(t, device, answer)
			if scenario != "allowed" {
				want := "access.denied"
				if scenario == "host-capability" || scenario == "device-capability" {
					want = "protocol.unsupported"
				}
				if frame := readEnvelope(t, device); frame.Type != "error" || frame.Payload["code"] != want {
					t.Fatalf("answer denial=%+v", frame)
				}
			} else {
				forwarded := readEnvelope(t, host)
				if forwarded.Type != "question.answer" || forwarded.RuntimeEpoch != epoch || forwarded.DeviceID != ticket.DeviceID || forwarded.UserID != ticket.UserID {
					t.Fatalf("answer lost binding: %+v", forwarded)
				}
				if frame := readEnvelope(t, device); frame.Type != "command.receipt" || frame.Payload["state"] != "received" {
					t.Fatalf("answer receipt=%+v", frame)
				}
				for _, state := range []string{"host_accepted", "dispatching", "settled"} {
					writeWireFrame(t, host, map[string]any{"v": 1, "type": "command.receipt", "request_id": requestID, "runtime_id": runtimeID, "runtime_epoch": epoch, "session_id": sessionID, "device_id": ticket.DeviceID,
						"payload": map[string]any{"state": state, "payload_sha256": forwarded.PayloadSHA256}})
					if frame := readEnvelope(t, device); frame.Type != "command.receipt" || frame.Payload["state"] != state {
						t.Fatalf("answer progress=%+v", frame)
					}
				}
				writeWireFrame(t, device, answer)
				if frame := readEnvelope(t, device); frame.Type != "command.receipt" || frame.Payload["state"] != "settled" {
					t.Fatalf("answer retry=%+v", frame)
				}
				answer["runtime_epoch"] = installationID
				writeWireFrame(t, device, answer)
				if frame := readEnvelope(t, device); frame.Type != "error" || frame.Payload["code"] != "runtime.changed" {
					t.Fatalf("stale answer=%+v", frame)
				}
			}
			if scenario != "missing-scope" {
				writeWireFrame(t, device, map[string]any{"v": 1, "type": "session.subscribe", "request_id": requestID, "runtime_id": runtimeID, "session_id": sessionID, "payload": map[string]any{}})
				ack := readEnvelope(t, device)
				forwarded := readEnvelope(t, host)
				wantQuestions := scenario != "host-capability" && scenario != "device-capability"
				if (forwarded.Payload["questions"] == true) != wantQuestions {
					t.Fatalf("question negotiation=%+v", forwarded)
				}
				const syncID = "77777777-7777-4777-8777-777777777777"
				frame := map[string]any{"v": 1, "type": "session.snapshot", "request_id": requestID, "runtime_id": runtimeID, "runtime_epoch": epoch, "session_id": sessionID, "subscription_id": ack.SubscriptionID, "sync_id": syncID,
					"payload": map[string]any{"cursor": 3, "records": []any{}, "has_more": false, "assistant": nil}}
				writeWireFrame(t, host, frame)
				if read := readEnvelope(t, device); read.Type != "session.snapshot" {
					t.Fatalf("session snapshot=%+v", read)
				}
				if wantQuestions {
					frame["type"], frame["payload"] = "question.snapshot", map[string]any{"revision": 1, "items": []any{map[string]any{"question_id": questionID, "expires_at": time.Now().Add(time.Minute), "questions": []any{map[string]any{"id": "plan", "question": "Continue?"}}}}}
					writeWireFrame(t, host, frame)
					if read := readEnvelope(t, device); read.Type != "question.snapshot" || read.SyncID != syncID {
						t.Fatalf("question snapshot=%+v", read)
					}
				}
			}
			writeEnvelope(t, host, "ping", map[string]any{})
			if frame := readEnvelope(t, host); frame.Type != "pong" {
				t.Fatalf("answer forwarded without authority or after settled: %+v", frame)
			}
		})
	}
}
