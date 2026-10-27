package httpapi_test

import (
	"encoding/json"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/store"
	"github.com/coder/websocket"
)

func TestProductionRoutingOwnerCrashRequiresFreshSyncAndPreservesCommandStages(t *testing.T) {
	// Two production relay children, one Host protocol fixture, one phone.
	// This is a bounded fault scenario, not a capacity/throughput benchmark.
	f := newRoutingFixture(t, 1, 2)
	pair := f.pairs[0]
	if _, err := f.db.ExecContext(f.ctx, `update runtime_grants set scope=jsonb_set(scope,'{actions}',(scope->'actions')||'["message.submit"]'::jsonb) where runtime_id=$1`, pair.runtime); err != nil {
		t.Fatal(err)
	}
	host := f.host(pair, "a", "command.relay.v1")
	ticket := f.ticket(pair, "message.submit")
	phone, err := capacityConnect(f.ctx, f.clients["b"], f.origin, "device", "DSH-Ticket "+ticket.Token, pair.phoneKey, pair, "command.relay.v1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = phone.CloseNow() })
	oldSync := f.snapshot(pair, host, phone)
	request := capacityID()
	submit := capacityWire{V: 1, Type: "message.submit", RequestID: request, RuntimeID: pair.runtime, SessionID: pair.session, Payload: capacityPayload(map[string]any{"mode": "queue", "content": []any{map[string]any{"type": "text", "text": "PRIVATE_CRASH_COMMAND_BODY"}}})}
	approvalWrite(t, f.ctx, phone, submit)
	forward, err := capacityRead(f.ctx, host)
	if err != nil || forward.Type != "message.submit" || forward.PayloadSHA256 == "" {
		t.Fatal("command not forwarded before fault", err)
	}
	expectReceipt := func(connection *websocket.Conn, state string) {
		t.Helper()
		frame, err := capacityRead(f.ctx, connection)
		var payload struct {
			State string `json:"state"`
		}
		if err != nil || frame.Type != "command.receipt" || frame.RequestID != request || json.Unmarshal(frame.Payload, &payload) != nil || payload.State != state {
			t.Fatal("incorrect command stage after fault", frame.Type, payload.State, err)
		}
	}
	expectReceipt(phone, "received")
	oldRoute := f.route(pair)
	process := f.nodes["a"].process
	if err := process.command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-process.done:
		process.stopped = true
		_ = process.log.Close()
		if err == nil {
			t.Fatal("fault did not terminate owner")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("owned relay child did not terminate")
	}
	f.closed(phone)
	f.closed(host)
	var state string
	if err := f.db.QueryRowContext(f.ctx, `select state from commands where request_id=$1`, request).Scan(&state); err != nil || state != "received" {
		t.Fatal("transport became a host acceptance", state, err)
	}
	// SIGKILL left real stale metadata: the scenario must not pass by deleting
	// routes, consuming records, changing leases or running graceful cleanup.
	if route := f.route(pair); route != oldRoute {
		t.Fatal("crash fixture cleared stale routing metadata")
	}
	pair.hostAPI.http, pair.phoneAPI.http = f.clients["b"], f.clients["b"]
	retryTicket := f.ticket(pair, "message.submit")
	if connection, err := capacityConnect(f.ctx, f.clients["b"], f.origin, "device", "DSH-Ticket "+retryTicket.Token, pair.phoneKey, pair, "command.relay.v1"); err == nil {
		_ = connection.CloseNow()
		t.Fatal("dead owner was silently replaced by a local content route")
	}
	pair.epoch = capacityID()
	replacement := f.host(pair, "b", "command.relay.v1")
	reconnected, err := capacityConnect(f.ctx, f.clients["b"], f.origin, "device", "DSH-Ticket "+retryTicket.Token, pair.phoneKey, pair, "command.relay.v1")
	if err != nil {
		t.Fatal("failed transport consumed usable ticket", err)
	}
	t.Cleanup(func() { _ = reconnected.CloseNow() })
	var status store.CommandStatus
	if err := pair.phoneAPI.call(f.ctx, "GET", "/v1/commands/"+request+"?device_id="+pair.device, nil, &status, 200); err != nil || status.State != "received" {
		t.Fatal("durable status changed on reconnect", status.State, err)
	}
	f.ping(replacement) // Reconnection must not replay the retained command body.
	approvalWrite(t, f.ctx, reconnected, capacityWire{V: 1, Type: "session.page", RequestID: capacityID(), RuntimeID: pair.runtime, RuntimeEpoch: oldSync.RuntimeEpoch, SessionID: pair.session, SubscriptionID: oldSync.SubscriptionID, Payload: capacityPayload(map[string]any{"sync_id": oldSync.SyncID, "through_seq": -1, "before_seq": 0, "max_messages": 10})})
	invalid, err := capacityRead(f.ctx, reconnected)
	var failure struct {
		Code string `json:"code"`
	}
	if err != nil || invalid.Type != "error" || json.Unmarshal(invalid.Payload, &failure) != nil || failure.Code != "protocol.resync_required" {
		t.Fatal("old sync was reused after owner crash", invalid.Type, failure.Code, err)
	}
	fresh := f.snapshot(pair, replacement, reconnected)
	if fresh.SubscriptionID == oldSync.SubscriptionID || fresh.SyncID == oldSync.SyncID || fresh.RuntimeEpoch == oldSync.RuntimeEpoch {
		t.Fatal("recovery did not replace the old sync identity")
	}
	// Only this explicit user-equivalent retry transfers the stable request.
	approvalWrite(t, f.ctx, reconnected, submit)
	resumed, err := capacityRead(f.ctx, replacement)
	if err != nil || resumed.Type != "message.submit" || resumed.RequestID != request || resumed.PayloadSHA256 != forward.PayloadSHA256 || resumed.RuntimeEpoch != pair.epoch {
		t.Fatal("explicit retry lost command identity", err)
	}
	expectReceipt(reconnected, "received")
	approvalWrite(t, f.ctx, replacement, map[string]any{"v": 1, "type": "command.receipt", "request_id": request, "runtime_id": pair.runtime, "runtime_epoch": pair.epoch, "session_id": pair.session, "device_id": pair.device, "payload": map[string]any{"state": "host_accepted", "payload_sha256": resumed.PayloadSHA256}})
	expectReceipt(reconnected, "host_accepted")
	approvalWrite(t, f.ctx, reconnected, submit)
	expectReceipt(reconnected, "host_accepted")
	timer := time.NewTimer(1100 * time.Millisecond)
	select {
	case <-timer.C:
	case <-f.ctx.Done():
		timer.Stop()
		t.Fatal(f.ctx.Err())
	}
	f.ping(replacement) // Accepted retries remain status-only, never a second forward.
	if current := f.route(pair); current.NodeID != f.nodes["b"].id || current.Generation != f.nodes["b"].generation {
		t.Fatal("old owner recovered route authority")
	}
}
