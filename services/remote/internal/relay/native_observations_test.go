package relay

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/hostmetrics"
	"dsh-mobile-ustc/services/remote/internal/observability"
	"dsh-mobile-ustc/services/remote/internal/store"
)

func nativeGolden(t *testing.T, name string) hostmetrics.Report {
	t.Helper()
	raw, err := os.ReadFile("../../../../contracts/ws/v1/golden/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var frame struct {
		Payload hostmetrics.Report `json:"payload"`
	}
	if json.Unmarshal(raw, &frame) != nil {
		t.Fatal("invalid golden")
	}
	return frame.Payload
}
func nativeOperationCount(t *testing.T, metrics *observability.Metrics, operation, result string) float64 {
	t.Helper()
	snapshot := metricsSnapshot(t, metrics)
	for _, metric := range snapshot["dsh_remote_host_native_operations_total"].GetMetric() {
		labels := map[string]string{}
		for _, label := range metric.Label {
			labels[label.GetName()] = label.GetValue()
		}
		if labels["operation"] == operation && labels["result"] == result {
			return metric.GetCounter().GetValue()
		}
	}
	return 0
}

func TestNativeObservationsAreOptionalHostOnlyAndConnectionScoped(t *testing.T) {
	key := relayTestKey(t)
	jwk, jkt := relayTestPublicJWK(t, key)
	const installation = "11111111-1111-4111-8111-111111111111"
	const runtime = "33333333-3333-4333-8333-333333333333"
	const epoch = "44444444-4444-4444-8444-444444444444"
	fake := &relayTestStore{hostCredential: store.HostCredentialIdentity{InstallationID: installation, KeyVersion: 1, PublicJWK: jwk, KeyThumbprint: jkt, ExpiresAt: time.Now().Add(time.Minute)}, detached: make(chan store.RuntimeConnection, 4),
		ticket: store.TicketRedemption{UserID: installation, DeviceID: "22222222-2222-4222-8222-222222222222", RuntimeID: runtime, DeviceKeyVersion: 1, GrantVersion: 1, ProofPublicJWK: jwk, ProofKeyThumbprint: jkt, ExpiresAt: time.Now().Add(time.Minute), Scope: store.GrantScope{Actions: []string{"session.read"}, Workspaces: []string{}, Sessions: []string{}}}}
	if slices.Contains(New(fake).capabilities(), hostmetrics.Capability) {
		t.Fatal("disabled metrics advertised native observations")
	}
	relay := New(fake)
	metrics := observability.New()
	relay.ConfigureMetrics(metrics)
	server := httptest.NewServer(relay)
	t.Cleanup(server.Close)
	host := dialRelayHost(t, server.URL, key, installation, runtime, epoch, "connection.heartbeat.v1", hostmetrics.Capability)
	defer host.CloseNow()
	live := relay.hostForRuntime(runtime)
	if !live.supports(hostmetrics.Capability) {
		t.Fatal("Host did not negotiate observation capability")
	}
	first := nativeGolden(t, "host-observations")
	first.ConnectionID = live.connectionID
	frame := func(report hostmetrics.Report) map[string]any {
		return map[string]any{"v": 1, "type": "host.observations", "runtime_id": runtime, "runtime_epoch": epoch, "payload": report}
	}
	writeWireFrame(t, host, frame(first))
	metricUntil(t, func() bool { return nativeOperationCount(t, metrics, "checkpoint", "persisted") == 1 })
	writeWireFrame(t, host, frame(first))
	metricUntil(t, func() bool {
		return metricValue(t, metricsSnapshot(t, metrics), "host_observation_reports_total", map[string]string{"result": "throttled"}) == 1
	})
	time.Sleep(1050 * time.Millisecond)
	writeWireFrame(t, host, frame(first))
	metricUntil(t, func() bool {
		return metricValue(t, metricsSnapshot(t, metrics), "host_observation_reports_total", map[string]string{"result": "duplicate"}) == 1
	})
	time.Sleep(1050 * time.Millisecond)
	next := nativeGolden(t, "host-observations-next")
	next.ConnectionID = live.connectionID
	writeWireFrame(t, host, frame(next))
	metricUntil(t, func() bool { return nativeOperationCount(t, metrics, "checkpoint", "failed") == 1 })
	if nativeOperationCount(t, metrics, "checkpoint", "persisted") != 1 || nativeOperationCount(t, metrics, "prompt", "ok") != 1 {
		t.Fatal("cumulative report was added twice")
	}
	time.Sleep(1050 * time.Millisecond)
	bad := frame(next)
	payload, _ := json.Marshal(next)
	var object map[string]any
	_ = json.Unmarshal(payload, &object)
	object["tool_arguments"] = "PRIVATE_METRIC_BODY"
	bad["payload"] = object
	writeWireFrame(t, host, bad)
	metricUntil(t, func() bool {
		return metricValue(t, metricsSnapshot(t, metrics), "host_observation_reports_total", map[string]string{"result": "rejected"}) == 1
	})
	writeEnvelope(t, host, "ping", map[string]any{})
	if readEnvelope(t, host).Type != "pong" {
		t.Fatal("rejected observation interrupted ordinary Host traffic")
	}
	phone := dialRelayDevice(t, server.URL, key, fake.ticket, runtime, "connection.heartbeat.v1", hostmetrics.Capability, hostmetrics.JournalCapability)
	defer phone.CloseNow()
	peers := relay.devicesForRuntime(runtime, fake.ticket.DeviceID)
	if len(peers) != 1 || peers[0].supports(hostmetrics.Capability) || peers[0].supports(hostmetrics.JournalCapability) {
		t.Fatal("phone obtained Host-only capability")
	}
	writeWireFrame(t, phone, frame(next))
	if denied := readEnvelope(t, phone); denied.Type != "error" || denied.Payload["code"] != "access.denied" {
		t.Fatal("phone native metric forgery accepted", denied)
	}
	if nativeOperationCount(t, metrics, "checkpoint", "failed") != 1 {
		t.Fatal("phone changed native operation counter")
	}
	w := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	for _, private := range []string{runtime, epoch, installation, live.connectionID, "PRIVATE_METRIC_BODY"} {
		if strings.Contains(w.Body.String(), private) {
			t.Fatal("native observation exposed identity or text")
		}
	}
}

type nativeFencedRepository struct {
	Repository
	deny atomic.Bool
}

func (repository *nativeFencedRepository) TouchRuntimeConnection(ctx context.Context, a, b, c, d string) error {
	if repository.deny.Load() {
		return store.ErrRuntimeConnectionStale
	}
	return repository.Repository.TouchRuntimeConnection(ctx, a, b, c, d)
}

func TestNativeObservationsCannotReplaceCurrentOwnershipCheck(t *testing.T) {
	fake := &relayTestStore{}
	repository := &nativeFencedRepository{Repository: fake}
	repository.deny.Store(true)
	relay := New(repository)
	metrics := observability.New()
	relay.ConfigureMetrics(metrics)
	live := &liveConnection{peer: peer{role: "installation", installation: store.HostCredentialIdentity{InstallationID: "11111111-1111-4111-8111-111111111111"}}, runtimeID: "33333333-3333-4333-8333-333333333333", runtimeEpoch: "44444444-4444-4444-8444-444444444444", connectionID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", capabilities: capabilitySet([]string{hostmetrics.Capability})}
	relay.hosts[live.runtimeID] = live
	report := nativeGolden(t, "host-observations")
	raw, _ := json.Marshal(report)
	relay.routeHostObservations(t.Context(), live, wireEnvelope{Type: "host.observations", RuntimeID: live.runtimeID, RuntimeEpoch: live.runtimeEpoch, Payload: raw})
	if nativeOperationCount(t, metrics, "checkpoint", "persisted") != 0 || live.nativeReport != nil {
		t.Fatal("stale installation reported fresh native observations")
	}
}

func TestJournalObservationsRequireBothCapabilitiesOnAnAuthenticatedHost(t *testing.T) {
	for _, extension := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "journal"}[extension], func(t *testing.T) {
			key := relayTestKey(t)
			jwk, jkt := relayTestPublicJWK(t, key)
			const installation = "11111111-1111-4111-8111-111111111111"
			const runtime = "33333333-3333-4333-8333-333333333333"
			const epoch = "44444444-4444-4444-8444-444444444444"
			fake := &relayTestStore{hostCredential: store.HostCredentialIdentity{InstallationID: installation, KeyVersion: 1, PublicJWK: jwk, KeyThumbprint: jkt, ExpiresAt: time.Now().Add(time.Minute)}, detached: make(chan store.RuntimeConnection, 4)}
			if slices.Contains(New(fake).capabilities(), hostmetrics.JournalCapability) {
				t.Fatal("disabled metrics advertised journal observations")
			}
			relay := New(fake)
			metrics := observability.New()
			relay.ConfigureMetrics(metrics)
			server := httptest.NewServer(relay)
			t.Cleanup(server.Close)
			offered := []string{"connection.heartbeat.v1", hostmetrics.Capability}
			if extension {
				offered = append(offered, hostmetrics.JournalCapability)
			}
			host := dialRelayHost(t, server.URL, key, installation, runtime, epoch, offered...)
			defer host.CloseNow()
			live := relay.hostForRuntime(runtime)
			if live.supports(hostmetrics.JournalCapability) != extension {
				t.Fatal("incorrect journal capability negotiation")
			}
			report := nativeGolden(t, "host-observations-journal")
			report.ConnectionID = live.connectionID
			writeWireFrame(t, host, map[string]any{"v": 1, "type": "host.observations", "runtime_id": runtime, "runtime_epoch": epoch, "payload": report})
			if extension {
				metricUntil(t, func() bool {
					return nativeOperationCount(t, metrics, "journal_command", "persisted") == 1 && nativeOperationCount(t, metrics, "journal_approval", "failed") == 1
				})
			} else {
				metricUntil(t, func() bool {
					return metricValue(t, metricsSnapshot(t, metrics), "host_observation_reports_total", map[string]string{"result": "rejected"}) == 1
				})
				if nativeOperationCount(t, metrics, "journal_command", "persisted") != 0 || nativeOperationCount(t, metrics, "checkpoint", "persisted") != 0 {
					t.Fatal("partially applied an unnegotiated journal report")
				}
			}
			writeEnvelope(t, host, "ping", map[string]any{})
			if readEnvelope(t, host).Type != "pong" {
				t.Fatal("journal observation interrupted Host traffic")
			}
		})
	}
}
