package httpapi_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/files"
	"github.com/coder/websocket"
	jose "github.com/go-jose/go-jose/v4"
)

func stageFileMessageHost(t *testing.T, h *fileHTTPFixture, host *fileHost, offer files.FileOffer) {
	t.Helper()
	response, err := host.download(t, offer, host.key)
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != 200 || readErr != nil {
		t.Fatal("protected fixture download failed")
	}
	host.send(t, map[string]any{"v": 1, "type": "file.staged", "request_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "runtime_id": fileRuntimeID, "runtime_epoch": host.epoch, "session_id": h.session, "payload": map[string]any{"handoff_id": offer.HandoffID, "file_id": offer.FileID, "name": offer.Name, "size_bytes": offer.SizeBytes, "sha256": offer.SHA256}})
	if ack := host.read(t); string(ack["type"]) != `"file.staged.ack"` {
		t.Fatal("missing stage acknowledgement")
	}
}

type filePhone struct{ *fileHost }

func allowFileMessages(t *testing.T, h *fileHTTPFixture) {
	t.Helper()
	if _, err := h.database.ExecContext(h.ctx, `update runtime_grants set scope=jsonb_set(scope,'{actions}',(scope->'actions')||'["message.submit","command.status"]'::jsonb)`); err != nil {
		t.Fatal(err)
	}
}
func connectFilePhone(t *testing.T, h *fileHTTPFixture, caller *fileHTTPCaller, token, device string, fileCapability bool) *filePhone {
	t.Helper()
	code, raw := caller.call(token, "POST", "/v1/realtime/tickets", map[string]any{"runtime_id": fileRuntimeID, "scope": map[string]any{"actions": []string{"message.submit", "command.status", "session.read"}, "workspaces": []string{fileWorkspaceID}, "sessions": []string{}}})
	if code != 201 {
		t.Fatalf("phone ticket=%d", code)
	}
	var response struct {
		Data struct {
			Ticket string `json:"ticket"`
		} `json:"data"`
	}
	if json.Unmarshal(raw, &response) != nil {
		t.Fatal("bad phone ticket")
	}
	connection, _, err := websocket.Dial(h.ctx, strings.Replace(h.server.URL, "https://", "wss://", 1)+"/v1/realtime", &websocket.DialOptions{HTTPClient: h.server.Client(), Subprotocols: []string{"dsh.remote.v1"}, HTTPHeader: http.Header{"Authorization": []string{"DSH-Ticket " + response.Data.Ticket}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.CloseNow() })
	phone := &filePhone{&fileHost{fixture: h, connection: connection, key: caller.key}}
	challenge := phone.read(t)
	var proofChallenge struct {
		ConnectionID string `json:"connection_id"`
		ChallengeID  string `json:"challenge_id"`
		Nonce        string `json:"nonce"`
	}
	if json.Unmarshal(challenge["payload"], &proofChallenge) != nil {
		t.Fatal("invalid phone challenge")
	}
	caps := []string{"command.relay.v1", "connection.heartbeat.v1"}
	if fileCapability {
		caps = append(caps, files.MessageCapability)
	}
	sort.Strings(caps)
	proof := approvalSign(t, caller.key, jose.ES256, "", "dsh-relay-handshake-proof+jwt", map[string]any{"iss": device, "aud": auth.RelayHandshakeAudience, "challenge_id": proofChallenge.ChallengeID, "connection_id": proofChallenge.ConnectionID, "nonce": proofChallenge.Nonce, "runtime_id": fileRuntimeID, "hello_sha256": auth.RelayHelloDigest("device", device, "1", strings.Join(caps, "\n")), "iat": time.Now().Unix(), "jti": "file-message-phone-" + proofChallenge.ConnectionID}, nil)
	phone.send(t, map[string]any{"v": 1, "type": "hello.proof", "payload": map[string]any{"device_id": device, "protocols": []int{1}, "capabilities": caps, "proof": proof}})
	if ack := phone.read(t); string(ack["type"]) != `"hello.ok"` {
		t.Fatal("file phone hello failed")
	}
	return phone
}
func (p *filePhone) submit(t *testing.T, request, file string) {
	p.send(t, map[string]any{"v": 1, "type": "message.submit", "request_id": request, "runtime_id": fileRuntimeID, "session_id": p.fixture.session, "payload": map[string]any{"mode": "queue", "content": []any{map[string]any{"type": "text", "text": "Inspect the protected file."}, map[string]any{"type": "file", "file_id": file}}}})
}
func fileMessageState(t *testing.T, frame map[string]json.RawMessage) string {
	t.Helper()
	if string(frame["type"]) != `"command.receipt"` {
		t.Fatalf("expected receipt, got %s", frame["type"])
	}
	var payload struct {
		State string `json:"state"`
	}
	if json.Unmarshal(frame["payload"], &payload) != nil {
		t.Fatal("invalid receipt")
	}
	return payload.State
}

func fileMessageError(t *testing.T, frame map[string]json.RawMessage) string {
	t.Helper()
	if string(frame["type"]) != `"error"` {
		t.Fatalf("expected error, got %s", frame["type"])
	}
	var payload struct {
		Code string `json:"code"`
	}
	if json.Unmarshal(frame["payload"], &payload) != nil {
		t.Fatal("invalid protocol error")
	}
	return payload.Code
}

func TestFileMessageRelayRequiresAllNegotiatedCurrentDeviceReferences(t *testing.T) {
	h := newFileHTTPFixture(t)
	allowFileMessages(t, h)
	prepared := h.cleanForHandoff(t, []byte("referenced bytes"))
	host := connectFileHost(t, h, "command.relay.v1", files.MessageCapability)
	offer := host.offer(t)
	phone := connectFilePhone(t, h, h.caller, h.token, "33333333-3333-4333-8333-333333333333", true)
	phone.submit(t, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaab", offer.FileID)
	if fileMessageError(t, phone.read(t)) != "file.staging_required" {
		t.Fatal("unstaged file message admitted")
	}
	response, err := host.download(t, offer, host.key)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	host.send(t, map[string]any{"v": 1, "type": "file.staged", "request_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "runtime_id": fileRuntimeID, "runtime_epoch": host.epoch, "session_id": h.session, "payload": map[string]any{"handoff_id": offer.HandoffID, "file_id": offer.FileID, "name": offer.Name, "size_bytes": offer.SizeBytes, "sha256": offer.SHA256}})
	if ack := host.read(t); string(ack["type"]) != `"file.staged.ack"` {
		t.Fatal("missing stage ack")
	}
	other := connectFilePhone(t, h, h.second, h.secondToken, "88888888-8888-4888-8888-888888888888", true)
	other.submit(t, "cccccccc-cccc-4ccc-8ccc-cccccccccccc", offer.FileID)
	if fileMessageError(t, other.read(t)) != "access.denied" {
		t.Fatal("another device used original upload")
	}
	old := connectFilePhone(t, h, h.caller, h.token, "33333333-3333-4333-8333-333333333333", false)
	old.submit(t, "dddddddd-dddd-4ddd-8ddd-dddddddddddd", offer.FileID)
	if fileMessageError(t, old.read(t)) != "protocol.unsupported" {
		t.Fatal("unnegotiated file message admitted")
	}
	request := "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	phone.submit(t, request, prepared.File.ID)
	forwarded := host.read(t)
	if string(forwarded["type"]) != `"message.submit"` || !strings.Contains(string(forwarded["payload"]), offer.FileID) {
		t.Fatal("authorized file ID not forwarded")
	}
	if fileMessageState(t, phone.read(t)) != "received" {
		t.Fatal("missing received receipt")
	}
	var hash string
	_ = json.Unmarshal(forwarded["payload_sha256"], &hash)
	for _, state := range []string{"host_accepted", "agent_queued"} {
		host.send(t, map[string]any{"v": 1, "type": "command.receipt", "request_id": request, "runtime_id": fileRuntimeID, "runtime_epoch": host.epoch, "session_id": h.session, "device_id": "33333333-3333-4333-8333-333333333333", "payload": map[string]any{"state": state, "payload_sha256": hash}})
		if fileMessageState(t, phone.read(t)) != state {
			t.Fatal("host receipt not routed")
		}
	}
	host.send(t, map[string]any{"v": 1, "type": "file.release", "request_id": "ffffffff-ffff-4fff-8fff-ffffffffffff", "runtime_id": fileRuntimeID, "runtime_epoch": host.epoch, "session_id": h.session, "payload": map[string]any{"handoff_id": offer.HandoffID, "file_id": offer.FileID}})
	if ack := host.read(t); string(ack["type"]) != `"file.release.ack"` {
		t.Fatal("release missing")
	}
	phone.submit(t, request, offer.FileID)
	if fileMessageState(t, phone.read(t)) != "agent_queued" {
		t.Fatal("terminal retry required live receipt")
	}
	var commands, refs int
	if err := h.database.QueryRowContext(h.ctx, `select (select count(*) from commands),(select count(*) from file_message_refs)`).Scan(&commands, &refs); err != nil || commands != 1 || refs != 1 {
		t.Fatal("denied or repeated file commands persisted duplicate admission")
	}
}

func TestFileMessageDoesNotRaceAheadOfItsHostStageAcknowledgement(t *testing.T) {
	h := newFileHTTPFixture(t)
	allowFileMessages(t, h)
	h.cleanForHandoff(t, []byte("stage ordering bytes"))
	host := connectFileHost(t, h, "command.relay.v1", files.MessageCapability)
	offer := host.offer(t)
	// Fault injection models the small interval after the stage transaction but
	// before its ack has entered the current Host's socket queue.
	if _, err := h.database.ExecContext(h.ctx, `update file_handoffs set state='staged',staged_name=$2 where id=$1`, offer.HandoffID, offer.Name); err != nil {
		t.Fatal(err)
	}
	phone := connectFilePhone(t, h, h.caller, h.token, "33333333-3333-4333-8333-333333333333", true)
	phone.submit(t, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaac", offer.FileID)
	if fileMessageError(t, phone.read(t)) != "file.staging_required" {
		t.Fatal("file command outran stage ack")
	}
	var count int
	if err := h.database.QueryRowContext(h.ctx, `select count(*) from commands`).Scan(&count); err != nil || count != 0 {
		t.Fatal("not-ready file left a command")
	}
}

func TestFileMessageRequiresTheDestinationHostMessageCapability(t *testing.T) {
	h := newFileHTTPFixture(t)
	allowFileMessages(t, h)
	prepared := h.cleanForHandoff(t, []byte("legacy Host capability"))
	connectFileHost(t, h, "command.relay.v1")
	phone := connectFilePhone(t, h, h.caller, h.token, "33333333-3333-4333-8333-333333333333", true)
	phone.submit(t, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaae", prepared.File.ID)
	if fileMessageError(t, phone.read(t)) != "protocol.unsupported" {
		t.Fatal("legacy Host received unsupported file command")
	}
	var count int
	if err := h.database.QueryRowContext(h.ctx, `select count(*) from commands`).Scan(&count); err != nil || count != 0 {
		t.Fatal("unsupported file command persisted")
	}
}

func TestExpiredFileMessageUsesNegotiatedHostOnlyReconciliation(t *testing.T) {
	for _, supported := range []bool{true, false} {
		t.Run(map[bool]string{true: "capable", false: "legacy"}[supported], func(t *testing.T) {
			h := newFileHTTPFixture(t)
			allowFileMessages(t, h)
			h.cleanForHandoff(t, []byte("expired reconciliation source"))
			caps := []string{"command.relay.v1", files.MessageCapability}
			if supported {
				caps = append(caps, files.ReconcileCapability)
			}
			host := connectFileHost(t, h, caps...)
			offer := host.offer(t)
			stageFileMessageHost(t, h, host, offer)
			phone := connectFilePhone(t, h, h.caller, h.token, "33333333-3333-4333-8333-333333333333", true)
			request := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaf"
			phone.submit(t, request, offer.FileID)
			original := host.read(t)
			if string(original["type"]) != `"message.submit"` || fileMessageState(t, phone.read(t)) != "received" {
				t.Fatal("first file intent not recorded")
			}
			illegal := connectFilePhone(t, h, h.caller, h.token, "33333333-3333-4333-8333-333333333333", true)
			illegal.send(t, map[string]any{"v": 1, "type": "message.files.reconcile", "request_id": request, "runtime_id": fileRuntimeID, "session_id": h.session, "payload": map[string]any{"mode": "queue", "content": []any{map[string]any{"type": "file", "file_id": offer.FileID}}}})
			if fileMessageError(t, illegal.read(t)) != "protocol.unsupported" {
				t.Fatal("phone selected Host-only reconciliation")
			}
			host.send(t, map[string]any{"v": 1, "type": "file.release", "request_id": "ffffffff-ffff-4fff-8fff-ffffffffffff", "runtime_id": fileRuntimeID, "runtime_epoch": host.epoch, "session_id": h.session, "payload": map[string]any{"handoff_id": offer.HandoffID, "file_id": offer.FileID}})
			if ack := host.read(t); string(ack["type"]) != `"file.release.ack"` {
				t.Fatal("release missing")
			}
			if _, err := h.database.ExecContext(h.ctx, `update files set created_at=clock_timestamp()-interval '1 day',expires_at=clock_timestamp()-interval '1 second',state='expired' where id=$1`, offer.FileID); err != nil {
				t.Fatal(err)
			}
			phone.submit(t, request, offer.FileID)
			if !supported {
				if fileMessageError(t, phone.read(t)) != "file.staging_required" {
					t.Fatal("legacy Host got an unsafe fallback")
				}
				ctx, cancel := context.WithTimeout(h.ctx, 150*time.Millisecond)
				defer cancel()
				if _, _, err := host.connection.Read(ctx); err == nil {
					t.Fatal("legacy Host received a new message admission")
				}
				return
			}
			reconcile := host.read(t)
			if string(reconcile["type"]) != `"message.files.reconcile"` || string(reconcile["payload_sha256"]) != string(original["payload_sha256"]) {
				t.Fatal("reconciliation changed original operation or digest")
			}
			if fileMessageState(t, phone.read(t)) != "received" {
				t.Fatal("reconciliation acknowledgement missing")
			}
			var digest string
			_ = json.Unmarshal(original["payload_sha256"], &digest)
			host.send(t, map[string]any{"v": 1, "type": "command.receipt", "request_id": request, "runtime_id": fileRuntimeID, "runtime_epoch": host.epoch, "session_id": h.session, "device_id": "33333333-3333-4333-8333-333333333333", "payload": map[string]any{"state": "outcome_unknown", "payload_sha256": digest}})
			if fileMessageState(t, phone.read(t)) != "outcome_unknown" {
				t.Fatal("unknown native evidence was not preserved")
			}
			var count int
			if err := h.database.QueryRowContext(h.ctx, `select count(*) from file_message_refs`).Scan(&count); err != nil || count != 1 {
				t.Fatal("reconciliation added another file claim")
			}
		})
	}
}
