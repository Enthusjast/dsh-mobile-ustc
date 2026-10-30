package httpapi_test

import (
	"encoding/json"
	"testing"

	"dsh-mobile-ustc/services/remote/internal/store"
	"github.com/coder/websocket"
)

func TestProductionSharedCommandBudgetSurvivesOwnerMigrationAndFreshSocket(t *testing.T) {
	f := newRoutingFixture(t, 1, 4, store.CommandRateLimits{Version: 1, WindowMilliseconds: 60000, User: 100, Device: 2, Installation: 100, Session: 100})
	pair := f.pairs[0]
	if _, err := f.db.ExecContext(f.ctx, `update runtime_grants set scope=jsonb_set(scope,'{actions}',(scope->'actions')||'["message.submit"]'::jsonb) where runtime_id=$1`, pair.runtime); err != nil {
		t.Fatal(err)
	}
	connectPhone := func(node string) *websocket.Conn {
		t.Helper()
		ticket := f.ticket(pair, "message.submit")
		connection, err := capacityConnect(f.ctx, f.clients[node], f.origin, "device", "DSH-Ticket "+ticket.Token, pair.phoneKey, pair, "command.relay.v1")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = connection.CloseNow() })
		return connection
	}
	submit := func(phone, host *websocket.Conn) capacityWire {
		t.Helper()
		id := capacityID()
		approvalWrite(t, f.ctx, phone, capacityWire{V: 1, Type: "message.submit", RequestID: id, RuntimeID: pair.runtime, SessionID: pair.session, Payload: capacityPayload(map[string]any{"mode": "queue", "content": []any{map[string]any{"type": "text", "text": "PRIVATE_SHARED_RATE_BODY"}}})})
		forward, err := capacityRead(f.ctx, host)
		if err != nil || forward.Type != "message.submit" || forward.RequestID != id {
			t.Fatal("allowed attempt not forwarded", forward.Type, err)
		}
		frame := approvalRead(t, f.ctx, phone)
		var receipt struct {
			State string `json:"state"`
		}
		if frame.Type != "command.receipt" || frame.RequestID != id || json.Unmarshal(frame.Payload, &receipt) != nil || receipt.State != "received" {
			t.Fatal("allowed command not recorded", frame.Type, receipt.State)
		}
		return forward
	}
	hostA := f.host(pair, "a", "command.relay.v1")
	phoneA := connectPhone("b")
	_ = submit(phoneA, hostA)
	// Move the same runtime to another real process, then reprove the same device
	// on a fresh socket/ticket through the opposite ingress.
	pair.epoch = capacityID()
	hostB := f.host(pair, "b", "command.relay.v1")
	f.closed(hostA)
	f.closed(phoneA)
	phoneB := connectPhone("a")
	forward := submit(phoneB, hostB)
	deniedID := capacityID()
	approvalWrite(t, f.ctx, phoneB, capacityWire{V: 1, Type: "message.submit", RequestID: deniedID, RuntimeID: pair.runtime, SessionID: pair.session, Payload: capacityPayload(map[string]any{"mode": "queue", "content": []any{map[string]any{"type": "text", "text": "PRIVATE_LIMITED_BODY"}}})})
	denied := approvalRead(t, f.ctx, phoneB)
	var failure struct {
		Code string `json:"code"`
	}
	if denied.Type != "error" || denied.RequestID != deniedID || json.Unmarshal(denied.Payload, &failure) != nil || failure.Code != "rate.limited" {
		t.Fatal("new owner/socket bypassed shared quota", denied.Type, failure.Code)
	}
	f.ping(hostB) // A rejected body must not have reached the Host ahead of pong.
	var used, commands int
	if err := f.db.QueryRowContext(f.ctx, `select (select used from command_rate_counters where kind='device' and subject_id=$1),(select count(*) from commands where device_id=$1)`, pair.device).Scan(&used, &commands); err != nil || used != 2 || commands != 2 {
		t.Fatal("process migration reset or overspent quota", used, commands, err)
	}
	for _, state := range []string{"host_accepted", "dispatching", "settled"} {
		approvalWrite(t, f.ctx, hostB, capacityWire{V: 1, Type: "command.receipt", RequestID: forward.RequestID, RuntimeID: pair.runtime, RuntimeEpoch: pair.epoch, SessionID: pair.session, DeviceID: pair.device, Payload: capacityPayload(map[string]any{"state": state, "payload_sha256": forward.PayloadSHA256})})
		frame := approvalRead(t, f.ctx, phoneB)
		var result struct {
			State string `json:"state"`
		}
		if frame.Type != "command.receipt" || frame.RequestID != forward.RequestID || json.Unmarshal(frame.Payload, &result) != nil || result.State != state {
			t.Fatal("quota blocked existing Host result", frame.Type, result.State)
		}
	}
}
