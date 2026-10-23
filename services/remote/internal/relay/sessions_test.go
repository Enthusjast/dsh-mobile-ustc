package relay

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/store"
)

func TestSessionReadsRouteToOneConnectionAndRecheckScopeBeforeContent(t *testing.T) {
	key := relayTestKey(t)
	jwk, thumbprint := relayTestPublicJWK(t, key)
	const runtimeID = "33333333-3333-4333-8333-333333333333"
	const epoch = "44444444-4444-4444-8444-444444444444"
	const sessionID = "55555555-5555-4555-8555-555555555555"
	const requestID = "66666666-6666-4666-8666-666666666666"
	const syncID = "77777777-7777-4777-8777-777777777777"
	const installationID = "11111111-1111-4111-8111-111111111111"
	fake := &relayTestStore{
		ticket: store.TicketRedemption{UserID: installationID, DeviceID: "22222222-2222-4222-8222-222222222222", DeviceKeyVersion: 1,
			RuntimeID: runtimeID, GrantVersion: 1, ProofPublicJWK: jwk, ProofKeyThumbprint: thumbprint, ExpiresAt: time.Now().Add(time.Minute),
			Scope: store.GrantScope{Actions: []string{"session.read"}, Workspaces: []string{}, Sessions: []string{sessionID}}},
		hostCredential: store.HostCredentialIdentity{InstallationID: installationID, PublicJWK: jwk, KeyThumbprint: thumbprint, KeyVersion: 1, ExpiresAt: time.Now().Add(time.Minute)},
		detached:       make(chan store.RuntimeConnection, 2),
	}
	relayServer := New(fake)
	server := httptest.NewServer(relayServer)
	t.Cleanup(server.Close)
	host := dialRelayHost(t, server.URL, key, installationID, runtimeID, epoch)
	defer host.CloseNow()
	device := dialRelayDevice(t, server.URL, key, fake.ticket, runtimeID)
	defer device.CloseNow()
	other := dialRelayDevice(t, server.URL, key, fake.ticket, runtimeID)
	defer other.CloseNow()
	writeWireFrame(t, device, map[string]any{"v": 1, "type": "session.subscribe", "request_id": requestID, "runtime_id": runtimeID, "session_id": sessionID, "payload": map[string]any{}})
	ack := readEnvelope(t, device)
	if ack.Type != "session.subscribed" || !uuidPattern.MatchString(ack.SubscriptionID) || ack.RuntimeEpoch != epoch {
		t.Fatalf("missing subscription identity: %+v", ack)
	}
	forwarded := readEnvelope(t, host)
	if forwarded.Type != "session.subscribe" || forwarded.SubscriptionID != ack.SubscriptionID || forwarded.Payload["max_messages"] != float64(30) {
		t.Fatalf("unexpected forwarded subscribe: %+v", forwarded)
	}
	writeWireFrame(t, other, map[string]any{"v": 1, "type": "session.unsubscribe", "request_id": requestID, "runtime_id": runtimeID,
		"runtime_epoch": epoch, "session_id": sessionID, "subscription_id": ack.SubscriptionID, "payload": map[string]any{}})
	if denied := readEnvelope(t, other); denied.Type != "error" || denied.Payload["code"] != "protocol.resync_required" {
		t.Fatalf("other socket canceled subscription: %+v", denied)
	}
	send := func(kind, request string, payload any) {
		writeWireFrame(t, host, map[string]any{"v": 1, "type": kind, "request_id": request, "runtime_id": runtimeID, "runtime_epoch": epoch,
			"session_id": sessionID, "subscription_id": ack.SubscriptionID, "sync_id": syncID, "payload": payload})
	}
	send("session.snapshot", requestID, map[string]any{"cursor": 7, "records": []any{}, "has_more": true, "assistant": nil})
	if snapshot := readEnvelope(t, device); snapshot.Type != "session.snapshot" || snapshot.SyncID != syncID {
		t.Fatalf("snapshot not routed: %+v", snapshot)
	}
	send("assistant.chunk", requestID, map[string]any{"attemptId": "native-attempt", "revision": 1, "index": 0, "time": 1, "type": "chunk", "chunk": map[string]any{"type": "text-delta", "index": 0, "text": "中文"}})
	if chunk := readEnvelope(t, device); chunk.Type != "assistant.chunk" {
		t.Fatalf("assistant chunk not routed: %+v", chunk)
	}
	const pageID = "88888888-8888-4888-8888-888888888888"
	page := map[string]any{"v": 1, "type": "session.page", "request_id": pageID, "runtime_id": runtimeID, "runtime_epoch": epoch,
		"session_id": sessionID, "subscription_id": ack.SubscriptionID, "payload": map[string]any{"sync_id": syncID, "through_seq": 7, "before_seq": 8}}
	writeWireFrame(t, device, page)
	if forwarded := readEnvelope(t, host); forwarded.Type != "session.page" || forwarded.RequestID != pageID {
		t.Fatalf("page not forwarded: %+v", forwarded)
	}
	send("session.page.result", pageID, map[string]any{"records": []any{}, "has_more": false, "through_seq": 7})
	if result := readEnvelope(t, device); result.Type != "session.page.result" || result.RequestID != pageID {
		t.Fatalf("page response not routed: %+v", result)
	}
	previousSubscription := ack.SubscriptionID
	writeWireFrame(t, device, map[string]any{"v": 1, "type": "session.unsubscribe", "request_id": pageID, "runtime_id": runtimeID,
		"runtime_epoch": epoch, "session_id": sessionID, "subscription_id": previousSubscription, "payload": map[string]any{}})
	if cancel := readEnvelope(t, host); cancel.Type != "session.unsubscribe" || cancel.SubscriptionID != previousSubscription {
		t.Fatalf("unsubscribe did not reach the native follower: %+v", cancel)
	}
	if canceled := readEnvelope(t, device); canceled.Type != "session.unsubscribed" || canceled.SubscriptionID != previousSubscription {
		t.Fatalf("unsubscribe was not acknowledged: %+v", canceled)
	}
	send("session.event", requestID, map[string]any{"native_seq": 8, "type": "cursor", "time": 1, "data": map[string]any{}})
	// A new subscription must be routed separately, even if the request UUID is
	// reused after the old subscription was explicitly released.
	writeWireFrame(t, device, map[string]any{"v": 1, "type": "session.subscribe", "request_id": requestID, "runtime_id": runtimeID, "session_id": sessionID, "payload": map[string]any{}})
	ack = readEnvelope(t, device)
	if ack.Type != "session.subscribed" || ack.SubscriptionID == previousSubscription {
		t.Fatalf("late canceled content leaked into replacement subscription: %+v", ack)
	}
	if fresh := readEnvelope(t, host); fresh.Type != "session.subscribe" || fresh.SubscriptionID != ack.SubscriptionID {
		t.Fatalf("replacement subscription was not forwarded: %+v", fresh)
	}
	send("session.snapshot", requestID, map[string]any{"cursor": 8, "records": []any{}, "has_more": false, "assistant": nil})
	if snapshot := readEnvelope(t, device); snapshot.Type != "session.snapshot" {
		t.Fatalf("replacement snapshot not routed: %+v", snapshot)
	}
	fake.mu.Lock()
	fake.readErr = store.ErrAccessDenied
	calls := fake.readCalls
	fake.mu.Unlock()
	if calls < 5 {
		t.Fatalf("content frames did not recheck session scope: %d", calls)
	}
	send("session.event", requestID, map[string]any{"native_seq": 8, "type": "cursor", "time": 1, "data": map[string]any{}})
	if revoked := readEnvelope(t, device); revoked.Type != "session.error" || revoked.Payload["code"] != "access.denied" {
		t.Fatalf("revoked scope received content: %+v", revoked)
	}
	if cancel := readEnvelope(t, host); cancel.Type != "session.unsubscribe" || cancel.SubscriptionID != ack.SubscriptionID {
		t.Fatalf("revocation left native follower alive: %+v", cancel)
	}
	relayServer.mu.Lock()
	count := len(relayServer.subscriptions)
	relayServer.mu.Unlock()
	if count != 0 {
		t.Fatal("revoked subscription remains in routing table")
	}
	// The other authenticated connection received neither the snapshot nor the
	// assistant/page frames from its sibling connection.
	writeEnvelope(t, other, "ping", map[string]any{})
	if frame := readEnvelope(t, other); frame.Type != "pong" {
		t.Fatalf("session content leaked to sibling connection: %+v", frame)
	}
	fake.mu.Lock()
	fake.readErr = nil
	fake.mu.Unlock()
	writeWireFrame(t, device, map[string]any{"v": 1, "type": "session.subscribe", "request_id": requestID, "runtime_id": runtimeID, "session_id": sessionID, "payload": map[string]any{}})
	if frame := readEnvelope(t, device); frame.Type != "session.subscribed" {
		t.Fatalf("could not reopen before host disconnect: %+v", frame)
	}
	if frame := readEnvelope(t, host); frame.Type != "session.subscribe" {
		t.Fatalf("new subscription missing at host: %+v", frame)
	}
	_ = host.CloseNow()
	if frame := readEnvelope(t, device); frame.Type != "session.error" || frame.Payload["code"] != "runtime.changed" {
		t.Fatalf("host disconnect left stale content subscription: %+v", frame)
	}
	relayServer.mu.Lock()
	remaining := len(relayServer.subscriptions)
	relayServer.mu.Unlock()
	if remaining != 0 {
		t.Fatal("host disconnect did not release subscription metadata")
	}
}

func TestFragmentedSnapshotRequiresContinuousIndexesAndOneSyncIdentity(t *testing.T) {
	const requestID = "66666666-6666-4666-8666-666666666666"
	const syncID = "77777777-7777-4777-8777-777777777777"
	makeFrame := func(index int, sync string) wireEnvelope {
		payload, _ := json.Marshal(map[string]any{"type": "session.snapshot", "fragment_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "index": index, "count": 2, "data": "e30="})
		return wireEnvelope{Type: "session.fragment", RequestID: requestID, SyncID: sync, Payload: payload}
	}
	for _, variant := range []string{"complete", "skip-first", "repeat", "changed-sync"} {
		t.Run(variant, func(t *testing.T) {
			subscription := &sessionSubscription{requestID: requestID}
			if variant == "skip-first" {
				if validateSessionContent(subscription, makeFrame(1, syncID)) {
					t.Fatal("accepted missing first fragment")
				}
				return
			}
			if !validateSessionContent(subscription, makeFrame(0, syncID)) || subscription.ready {
				t.Fatal("partial snapshot became ready")
			}
			index, sync := 1, syncID
			if variant == "repeat" {
				index = 0
			}
			if variant == "changed-sync" {
				sync = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
			}
			valid := validateSessionContent(subscription, makeFrame(index, sync))
			if valid != (variant == "complete") {
				t.Fatalf("variant %s validity=%t", variant, valid)
			}
			if valid && !subscription.ready {
				t.Fatal("complete snapshot did not activate sync")
			}
		})
	}
}
