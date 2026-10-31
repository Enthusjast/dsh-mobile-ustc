package relay

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/observability"
	"dsh-mobile-ustc/services/remote/internal/store"
	"github.com/coder/websocket"
)

func TestSendQueueLimitsRejectAmbiguousOrUnboundedConfiguration(t *testing.T) {
	good := `{"v":1,"ordinary_bytes":65536,"control_bytes":65536}`
	for _, raw := range []string{good, `{}`, `null`, `[]`, good + good,
		strings.Replace(good, `"v":1`, `"v":null`, 1),
		strings.Replace(good, `"v":1`, `"v":2`, 1),
		strings.Replace(good, `"ordinary_bytes"`, `"Ordinary_bytes"`, 1),
		strings.Replace(good, `"v":1`, `"v":1,"v":1`, 1),
		strings.Replace(good, `"control_bytes":65536`, `"control_bytes":null`, 1),
		strings.Replace(good, `"control_bytes":65536`, `"control_bytes":65537`, 1),
		strings.Replace(good, `"ordinary_bytes":65536`, `"ordinary_bytes":65535`, 1),
		strings.Replace(good, `"ordinary_bytes":65536`, `"ordinary_bytes":8589934593`, 1),
		strings.Replace(good, `"control_bytes":65536`, `"control_bytes":1.5`, 1),
		strings.Replace(good, `"v":1`, `"v":1,"extra":true`, 1)} {
		_, err := ParseSendQueueLimits([]byte(raw))
		if (err == nil) != (raw == good) {
			t.Fatal("node payload budget validation mismatch", err)
		}
	}
	if err := DefaultSendQueueLimits().Validate(); err != nil {
		t.Fatal(err)
	}
}

func newBudgetRelay(t *testing.T, ordinary int64) (*Server, []*liveConnection, []*websocket.Conn, *observability.Metrics) {
	t.Helper()
	key := relayTestKey(t)
	jwk, jkt := relayTestPublicJWK(t, key)
	const installation = "11111111-1111-4111-8111-111111111111"
	const epoch = "44444444-4444-4444-8444-444444444444"
	fake := &relayTestStore{hostCredential: store.HostCredentialIdentity{InstallationID: installation, KeyVersion: 1, PublicJWK: jwk, KeyThumbprint: jkt, ExpiresAt: time.Now().Add(time.Minute)}, detached: make(chan store.RuntimeConnection, 16)}
	relay := New(fake)
	if err := relay.ConfigureSendQueueLimits(SendQueueLimits{1, ordinary, maxFrameBytes}); err != nil {
		t.Fatal(err)
	}
	metrics := observability.New()
	relay.ConfigureMetrics(metrics)
	server := httptest.NewServer(relay)
	t.Cleanup(server.Close)
	lives, peers := []*liveConnection{}, []*websocket.Conn{}
	for _, runtime := range []string{"33333333-3333-4333-8333-333333333333", "55555555-5555-4555-8555-555555555555"} {
		peer := dialRelayHost(t, server.URL, key, installation, runtime, epoch)
		peer.SetReadLimit(maxFrameBytes)
		t.Cleanup(func() { _ = peer.CloseNow() })
		lives, peers = append(lives, relay.hostForRuntime(runtime)), append(peers, peer)
	}
	metricUntil(t, func() bool { used, _ := relay.sendBudget.snapshot(); return used == [2]int64{} })
	return relay, lives, peers, metrics
}

func exactBudgetPayload(t *testing.T, size int) map[string]any {
	t.Helper()
	value := map[string]any{"v": 1, "type": "budget.fixture", "payload": map[string]string{"padding": ""}}
	raw, _ := json.Marshal(value)
	value["payload"] = map[string]string{"padding": strings.Repeat("x", size-len(raw))}
	return value
}

func holdBudgetWriter(t *testing.T, ctx context.Context, live *liveConnection, payload any) (func(), <-chan error) {
	t.Helper()
	started, gate, result := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var once sync.Once
	release := func() { once.Do(func() { close(gate) }) }
	t.Cleanup(release)
	go func() {
		result <- live.sendJSONBeforeWrite(ctx, payload, func() error { close(started); <-gate; return nil })
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("writer did not reach payload gate")
	}
	return release, result
}

func TestNodeSendBudgetIncludesOtherConnectionsAndInflightButKeepsControlReserve(t *testing.T) {
	server, lives, peers, metrics := newBudgetRelay(t, maxFrameBytes)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	release, first := holdBudgetWriter(t, ctx, lives[0], exactBudgetPayload(t, maxFrameBytes))
	if err := lives[1].sendJSON(context.Background(), map[string]any{"type": "budget.fixture"}); !errors.Is(err, errRelayQueueFull) {
		t.Fatal("a second connection bypassed the node payload budget", err)
	}
	control := queuePriorityFrame(lives[1], "approval.reference", "control-reserve")
	if frame := readEnvelope(t, peers[1]); frame.Type != "approval.reference" {
		t.Fatal("ordinary node backlog starved a control notice")
	}
	if err := <-control; err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled wait changed its result", err)
	}
	lives[0].stop()
	used, _ := server.sendBudget.snapshot()
	if used != [2]int64{maxFrameBytes, 0} {
		t.Fatal("cancel/stop released an in-flight writer early", used)
	}
	snapshot := metricsSnapshot(t, metrics)
	if metricValue(t, snapshot, "relay_send_reserved_bytes", map[string]string{"lane": "ordinary"}) != maxFrameBytes ||
		metricValue(t, snapshot, "relay_send_limit_bytes", map[string]string{"lane": "control"}) != maxFrameBytes {
		t.Fatal("node payload metrics omitted in-flight reservations")
	}
	release()
	_ = readEnvelope(t, peers[0])
	metricUntil(t, func() bool { used, _ := server.sendBudget.snapshot(); return used == [2]int64{} })
	next := queuePriorityFrame(lives[1], "budget.fixture", "capacity-reused")
	_ = readEnvelope(t, peers[1])
	if err := <-next; err != nil {
		t.Fatal("writer completion leaked node capacity", err)
	}
}

func TestNodeSendBudgetRetainsCancelledQueuedFramesAndReleasesOnlyStoppedQueue(t *testing.T) {
	server, lives, peers, _ := newBudgetRelay(t, 2*maxFrameBytes)
	release, first := holdBudgetWriter(t, context.Background(), lives[0], exactBudgetPayload(t, maxFrameBytes))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	second := make(chan error, 1)
	go func() { second <- lives[0].sendJSON(ctx, exactBudgetPayload(t, maxFrameBytes)) }()
	metricUntil(t, func() bool { used, _ := server.sendBudget.snapshot(); return used[0] == 2*maxFrameBytes })
	cancel()
	if err := <-second; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if used, _ := server.sendBudget.snapshot(); used[0] != 2*maxFrameBytes {
		t.Fatal("cancelled queued payload lost its reservation")
	}
	lives[0].stop()
	lives[0].stop()
	if used, _ := server.sendBudget.snapshot(); used[0] != maxFrameBytes {
		t.Fatal("queue stop released an in-flight payload or leaked waiting data", used)
	}
	release()
	_ = readEnvelope(t, peers[0])
	<-first
	metricUntil(t, func() bool { used, _ := server.sendBudget.snapshot(); return used == [2]int64{} })
}

func TestNodeSendBudgetClosesWriterWithoutLosingOrLeakingReservations(t *testing.T) {
	server, lives, peers, metrics := newBudgetRelay(t, maxFrameBytes)
	release, result := holdBudgetWriter(t, context.Background(), lives[0], exactBudgetPayload(t, maxFrameBytes))
	_ = peers[0].CloseNow()
	select {
	case <-lives[0].done:
	case <-time.After(time.Second):
		t.Fatal("closed peer did not stop its queue")
	}
	metricUntil(t, func() bool {
		server.mu.Lock()
		defer server.mu.Unlock()
		_, present := server.connections[lives[0].conn]
		return !present
	})
	if used, _ := server.sendBudget.snapshot(); used[0] != maxFrameBytes {
		t.Fatal("retiring writer lost its outstanding reservation")
	}
	if metricValue(t, metricsSnapshot(t, metrics), "relay_send_reserved_bytes", map[string]string{"lane": "ordinary"}) != maxFrameBytes {
		t.Fatal("node metrics forgot a writer removed from active routes")
	}
	release()
	if err := <-result; err == nil {
		t.Fatal("closed writer reported a successful send")
	}
	metricUntil(t, func() bool { used, _ := server.sendBudget.snapshot(); return used == [2]int64{} })
}

func TestNodeSendBudgetControlExhaustionDoesNotBorrowOrdinaryCapacity(t *testing.T) {
	server, lives, peers, _ := newBudgetRelay(t, maxFrameBytes)
	const kind = "approval.reference"
	payload := exactBudgetPayload(t, maxFrameBytes-(len(kind)-len("budget.fixture")))
	payload["type"] = kind
	release, first := holdBudgetWriter(t, context.Background(), lives[0], payload)
	if err := lives[1].sendJSON(context.Background(), map[string]any{"type": kind}); !errors.Is(err, errRelayQueueFull) {
		t.Fatal("control budget overflow borrowed ordinary bytes", err)
	}
	ordinary := queuePriorityFrame(lives[1], "budget.fixture", "ordinary-reserve")
	_ = readEnvelope(t, peers[1])
	if err := <-ordinary; err != nil {
		t.Fatal("control exhaustion consumed ordinary capacity", err)
	}
	release()
	_ = readEnvelope(t, peers[0])
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	metricUntil(t, func() bool { used, _ := server.sendBudget.snapshot(); return used == [2]int64{} })
}

func bareBudgetConnection(budget *sendQueueBudget) *liveConnection {
	return &liveConnection{sendBudget: budget, sendQueue: make(chan outboundFrame, ordinaryQueueFrames), controlQueue: make(chan outboundFrame, controlQueueFrames), queueWake: make(chan struct{}, 1), done: make(chan struct{})}
}

func TestNodeSendBudgetAdmissionIsAtomicAndFailedQueueClaimsRollBack(t *testing.T) {
	budget := &sendQueueBudget{limits: SendQueueLimits{1, maxFrameBytes, maxFrameBytes}}
	var callers sync.WaitGroup
	var accepted atomic.Int32
	lives := []*liveConnection{}
	start := make(chan struct{})
	for range 16 {
		live := bareBudgetConnection(budget)
		lives = append(lives, live)
		callers.Go(func() {
			<-start
			if err := live.queueFrame(context.Background(), outboundFrame{body: make([]byte, maxFrameBytes)}); err == nil {
				accepted.Add(1)
			} else if !errors.Is(err, errRelayQueueFull) {
				t.Error(err)
			}
		})
	}
	close(start)
	callers.Wait()
	if accepted.Load() != 1 {
		t.Fatal("concurrent connections exceeded the shared node budget", accepted.Load())
	}
	for _, live := range lives {
		live.stop()
	}
	if used, _ := budget.snapshot(); used != [2]int64{} {
		t.Fatal("stopped connections leaked capacity", used)
	}
	for _, control := range []bool{false, true} {
		live := bareBudgetConnection(budget)
		count := ordinaryQueueFrames
		if control {
			count = controlQueueFrames
		}
		for range count {
			if err := live.queueFrame(context.Background(), outboundFrame{body: []byte("x"), control: control}); err != nil {
				t.Fatal(err)
			}
		}
		if err := live.queueFrame(context.Background(), outboundFrame{body: []byte("x"), control: control}); !errors.Is(err, errRelayQueueFull) {
			t.Fatal("per-connection frame overflow accepted", err)
		}
		if used, _ := budget.snapshot(); used[sendBudgetLane(control)] != int64(count) {
			t.Fatal("rejected frame retained a node reservation", used)
		}
		live.stop()
	}
	if used, _ := budget.snapshot(); used != [2]int64{} {
		t.Fatal("lane cleanup leaked capacity", used)
	}
}

func TestNodeSendBudgetConfigurationCannotResetAnActiveOrRetiringBudget(t *testing.T) {
	server := New(nil)
	limits := DefaultSendQueueLimits()
	if err := server.ConfigureSendQueueLimits(limits); err != nil {
		t.Fatal(err)
	}
	if err := server.ConfigureSendQueueLimits(limits); err == nil {
		t.Fatal("node payload budget was reset")
	}
	server = New(nil)
	live, ok := server.registerConnection(nil, peer{}, nil)
	if !ok {
		t.Fatal("fixture connection registration failed")
	}
	server.unregisterConnection(live)
	if err := server.ConfigureSendQueueLimits(limits); err == nil {
		t.Fatal("retired connections allowed resetting writer reservations")
	}
}
