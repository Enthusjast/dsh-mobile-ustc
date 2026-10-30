package relay

import (
	"context"
	"errors"
	"net"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/store"
	"github.com/coder/websocket"
)

func blockedRelayWriter(t *testing.T) (*liveConnection, *websocket.Conn, func()) {
	t.Helper()
	key := relayTestKey(t)
	jwk, jkt := relayTestPublicJWK(t, key)
	const installation = "11111111-1111-4111-8111-111111111111"
	const runtime = "33333333-3333-4333-8333-333333333333"
	const epoch = "44444444-4444-4444-8444-444444444444"
	fake := &relayTestStore{hostCredential: store.HostCredentialIdentity{InstallationID: installation, KeyVersion: 1, PublicJWK: jwk, KeyThumbprint: jkt, ExpiresAt: time.Now().Add(time.Minute)}, detached: make(chan store.RuntimeConnection, 1)}
	relay := New(fake)
	server := httptest.NewServer(relay)
	t.Cleanup(server.Close)
	host := dialRelayHost(t, server.URL, key, installation, runtime, epoch)
	t.Cleanup(func() { _ = host.CloseNow() })
	live := relay.hostForRuntime(runtime)
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	resume := func() { once.Do(func() { close(release) }) }
	t.Cleanup(resume)
	go func() {
		_ = live.sendJSONBeforeWrite(context.Background(), map[string]any{"v": 1, "type": "priority.fixture", "payload": map[string]any{"id": "inflight"}}, func() error { close(started); <-release; return nil })
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("writer did not reach gate")
	}
	return live, host, resume
}

func queuePriorityFrame(live *liveConnection, kind, id string) <-chan error {
	result := make(chan error, 1)
	go func() {
		result <- live.sendJSON(context.Background(), map[string]any{"v": 1, "type": kind, "payload": map[string]string{"id": id}})
	}()
	return result
}

func TestControlNoticeCanEnterAndPassAFullOrdinaryQueue(t *testing.T) {
	live, host, resume := blockedRelayWriter(t)
	for index := range cap(live.sendQueue) {
		queuePriorityFrame(live, "priority.fixture", "ordinary")
		want := int64(index + 1)
		metricUntil(t, func() bool { live.queueMu.Lock(); defer live.queueMu.Unlock(); return live.queuedMessages == want })
	}
	control := queuePriorityFrame(live, "approval.invalidate", "negative-authority")
	select {
	case err := <-control:
		t.Fatal("critical control notice was rejected by ordinary backlog", err)
	case <-time.After(20 * time.Millisecond):
	}
	metricUntil(t, func() bool { live.queueMu.Lock(); defer live.queueMu.Unlock(); return live.queuedMessages == 17 })
	resume()
	if frame := readEnvelope(t, host); frame.Payload["id"] != "inflight" {
		t.Fatal("in-flight write changed", frame)
	}
	if frame := readEnvelope(t, host); frame.Type != "approval.invalidate" {
		t.Fatal("control notice remained behind session backlog", frame)
	}
	if err := <-control; err != nil {
		t.Fatal(err)
	}
	for range cap(live.sendQueue) {
		if frame := readEnvelope(t, host); frame.Type != "priority.fixture" {
			t.Fatal("ordinary FIFO lost", frame)
		}
	}
}

func TestControlBurstPreservesOrdinaryProgressAndControlFIFO(t *testing.T) {
	live, host, resume := blockedRelayWriter(t)
	for index, kind := range []string{"priority.fixture", "priority.fixture", "approval.reference", "approval.reference", "approval.reference", "approval.reference", "approval.reference", "approval.reference"} {
		queuePriorityFrame(live, kind, string(rune('a'+index)))
		want := int64(index + 1)
		metricUntil(t, func() bool { live.queueMu.Lock(); defer live.queueMu.Unlock(); return live.queuedMessages == want })
	}
	resume()
	_ = readEnvelope(t, host)
	for _, id := range []string{"c", "d", "e", "f", "a", "g", "h", "b"} {
		if frame := readEnvelope(t, host); frame.Payload["id"] != id {
			t.Fatal("priority fairness or lane FIFO changed", id, frame)
		}
	}
}

func TestOrdinaryQueueStillRejectsOverflow(t *testing.T) {
	live, _, _ := blockedRelayWriter(t)
	for index := range cap(live.sendQueue) {
		queuePriorityFrame(live, "priority.fixture", "ordinary")
		want := int64(index + 1)
		metricUntil(t, func() bool { live.queueMu.Lock(); defer live.queueMu.Unlock(); return live.queuedMessages == want })
	}
	if err := live.sendJSON(context.Background(), map[string]any{"v": 1, "type": "priority.fixture", "payload": map[string]any{}}); !errors.Is(err, errRelayQueueFull) {
		t.Fatal("ordinary overflow escaped its limit", err)
	}
}

func TestControlReserveHasIndependentFrameAndByteLimitsAndStopReleasesBothLanes(t *testing.T) {
	for _, limit := range []string{"frames", "bytes"} {
		t.Run(limit, func(t *testing.T) {
			live, _, _ := blockedRelayWriter(t)
			count, padding := controlQueueFrames, "small"
			if limit == "bytes" {
				count = 2
				padding = strings.Repeat("x", 50*1024)
			}
			payload := map[string]any{"v": 1, "type": "approval.snapshot", "payload": map[string]string{"id": padding}}
			waiting := []<-chan error{}
			for index := range count {
				result := make(chan error, 1)
				go func() { result <- live.sendJSON(context.Background(), payload) }()
				waiting = append(waiting, result)
				want := int64(index + 1)
				metricUntil(t, func() bool { live.queueMu.Lock(); defer live.queueMu.Unlock(); return live.queuedMessages == want })
			}
			if err := live.sendJSON(context.Background(), payload); !errors.Is(err, errRelayQueueFull) {
				t.Fatal("control reserve exceeded its", limit, "limit", err)
			}
			waiting = append(waiting, queuePriorityFrame(live, "priority.fixture", "ordinary-reserve"))
			metricUntil(t, func() bool {
				live.queueMu.Lock()
				defer live.queueMu.Unlock()
				return live.queuedMessages == int64(count+1)
			})
			live.queueMu.Lock()
			validAccounting := live.controlQueuedBytes <= controlQueueBytes && len(live.controlQueue) <= controlQueueFrames && live.queuedBytes >= live.controlQueuedBytes
			live.queueMu.Unlock()
			if !validAccounting {
				t.Fatal("invalid aggregate queue accounting")
			}
			live.stop()
			for _, result := range waiting {
				select {
				case err := <-result:
					if !errors.Is(err, net.ErrClosed) {
						t.Fatal("stopped waiter did not close", err)
					}
				case <-time.After(time.Second):
					t.Fatal("stopped queue retained its sender")
				}
			}
			live.queueMu.Lock()
			defer live.queueMu.Unlock()
			if live.queuedBytes != 0 || live.queuedMessages != 0 || live.controlQueuedBytes != 0 || len(live.sendQueue) != 0 || len(live.controlQueue) != 0 {
				t.Fatal("stop retained queued frames or accounting")
			}
		})
	}
}

func TestControlPriorityIsAnExplicitMetadataAllowlist(t *testing.T) {
	for _, kind := range []string{"access.revoked", "runtime.changed", "server.draining", "approval.invalidate", "approval.decision", "approval.reference", "approval.snapshot", "approval.registered", "approval.result.ack", "approval.details.get", "approval.unsubscribed"} {
		if !priorityControlFrame([]byte(`{"v":1,"type":"` + kind + `","payload":{}}`)) {
			t.Fatal("control metadata lost priority", kind)
		}
	}
	for _, kind := range []string{"approval.details", "approval.fragment", "approval.request", "approval.error", "approval.reference.fake", "assistant.chunk", "session.snapshot", "command.receipt", "message.submit", "error"} {
		if priorityControlFrame([]byte(`{"v":1,"type":"` + kind + `","payload":{}}`)) {
			t.Fatal("bulk or unknown frames consumed control reserve", kind)
		}
	}
}
