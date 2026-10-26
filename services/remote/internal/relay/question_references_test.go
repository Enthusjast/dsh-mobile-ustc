package relay

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/store"
	"github.com/coder/websocket"
)

type questionReferenceTestStore struct {
	*relayTestStore
	questions                     []store.QuestionReferenceItem
	questionCalls                 int
	questionSequence, questionKey int64
	questionConnection            store.RuntimeConnection
}

func (fake *questionReferenceTestStore) SyncRealtimeQuestionReferences(_ context.Context, connection store.RuntimeConnection, keyVersion, sequence int64, items []store.QuestionReferenceItem) error {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.questions = append([]store.QuestionReferenceItem{}, items...)
	fake.questionCalls++
	fake.questionSequence = sequence
	fake.questionKey = keyVersion
	fake.questionConnection = connection
	return nil
}
func TestQuestionReferencesRelayRequiresTheNegotiatedCurrentHostAndStrictMetadata(t *testing.T) {
	key := relayTestKey(t)
	jwk, jkt := relayTestPublicJWK(t, key)
	const installation = "11111111-1111-4111-8111-111111111111"
	const runtimeID = "33333333-3333-4333-8333-333333333333"
	const epoch = "44444444-4444-4444-8444-444444444444"
	const id = "55555555-5555-4555-8555-555555555555"
	fake := &questionReferenceTestStore{relayTestStore: &relayTestStore{hostCredential: store.HostCredentialIdentity{InstallationID: installation, PublicJWK: jwk, KeyThumbprint: jkt, KeyVersion: 3, ExpiresAt: time.Now().Add(time.Minute)}, detached: make(chan store.RuntimeConnection, 3)}}
	handler := New(fake)
	if !slices.Contains(handler.capabilities(), questionReferencesCapability) || slices.Contains(New(fake.relayTestStore).capabilities(), questionReferencesCapability) {
		t.Fatal("unimplemented metadata capability advertised")
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	connection := dialRelayHost(t, server.URL, key, installation, runtimeID, epoch, "command.relay.v1", "connection.heartbeat.v1", "session.catalog.v1", questionReferencesCapability)
	t.Cleanup(func() { _ = connection.Close(websocket.StatusNormalClosure, "done") })
	item := map[string]any{"question_id": id, "session_id": id, "kind": "timed_question", "state": "continued", "expires_at": nil}
	frame := map[string]any{"v": 1, "type": "question.references", "request_id": id, "runtime_id": runtimeID, "runtime_epoch": epoch, "payload": map[string]any{"sequence": 1, "items": []any{item}}}
	writeWireFrame(t, connection, frame)
	ack := readEnvelope(t, connection)
	if ack.Type != "question.references.ack" || ack.RequestID != id || ack.Payload["sequence"] != float64(1) || ack.Payload["item_count"] != float64(1) {
		t.Fatal("unexpected metadata acknowledgement", ack)
	}
	fake.mu.Lock()
	calls, version, sequence, binding := fake.questionCalls, fake.questionKey, fake.questionSequence, fake.questionConnection
	fake.mu.Unlock()
	if calls != 1 || version != 3 || sequence != 1 || binding.RuntimeID != runtimeID || binding.RuntimeEpoch != epoch || binding.ConnectionID == "" {
		t.Fatal("metadata did not use authenticated connection identity")
	}
	for _, change := range []func(){
		func() { frame["runtime_epoch"] = id },
		func() { item["questions"] = "PRIVATE_MUST_REJECT" },
		func() { delete(item, "expires_at") },
		func() { item["state"] = "approved" },
		func() { frame["session_id"] = id },
	} {
		change()
		writeWireFrame(t, connection, frame)
		failure := readEnvelope(t, connection)
		if failure.Type != "error" || failure.Payload["code"] != "protocol.invalid" {
			t.Fatal("invalid metadata accepted", failure)
		}
		frame["runtime_epoch"] = epoch
		delete(frame, "session_id")
		delete(item, "questions")
		item["expires_at"] = nil
		item["state"] = "continued"
	}
	fake.mu.Lock()
	calls = fake.questionCalls
	fake.mu.Unlock()
	if calls != 1 {
		t.Fatal("invalid data reached the metadata store")
	}
	deviceKey := relayTestKey(t)
	deviceJWK, deviceJKT := relayTestPublicJWK(t, deviceKey)
	fake.mu.Lock()
	fake.ticket = store.TicketRedemption{DeviceID: id, UserID: installation, RuntimeID: runtimeID, DeviceKeyVersion: 1, ProofKeyThumbprint: deviceJKT, ProofPublicJWK: deviceJWK, GrantVersion: 1, Scope: store.GrantScope{Actions: []string{"session.read", "question.answer"}, Sessions: []string{id}}, ExpiresAt: time.Now().Add(time.Minute)}
	ticket := fake.ticket
	fake.mu.Unlock()
	device := dialRelayDevice(t, server.URL, deviceKey, ticket, runtimeID, "command.relay.v1", "connection.heartbeat.v1", questionReferencesCapability)
	t.Cleanup(func() { _ = device.Close(websocket.StatusNormalClosure, "done") })
	writeWireFrame(t, device, frame)
	if failure := readEnvelope(t, device); failure.Type != "error" || failure.Payload["code"] != "access.denied" {
		t.Fatal("device forged a native question source", failure)
	}
}

func TestQuestionReferencesSharedWireMetadata(t *testing.T) {
	_, source, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(source), "../../../../contracts/push/v1/golden/question-references.json"))
	if err != nil {
		t.Fatal(err)
	}
	frame, err := decodeWireFrame(raw)
	if err != nil || frame.Type != "question.references" {
		t.Fatal("shared metadata frame rejected", err)
	}
	var payload struct {
		Sequence int64                         `json:"sequence"`
		Items    []store.QuestionReferenceItem `json:"items"`
	}
	if decodePayload(frame.Payload, &payload) != nil || payload.Sequence != 1 || len(payload.Items) != 2 {
		t.Fatal("shared reference payload changed")
	}
	for _, item := range payload.Items {
		if !item.Valid() {
			t.Fatal("shared native state rejected")
		}
	}
	if payload.Items[0].ExpiresAt == nil || payload.Items[1].ExpiresAt != nil || payload.Items[1].State != "continued" {
		t.Fatal("native deadline semantics changed")
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(frame.Payload, &fields)
	if len(fields) != 2 {
		t.Fatal("source payload grew additional private fields")
	}
}
