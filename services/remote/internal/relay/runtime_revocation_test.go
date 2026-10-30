package relay

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/observability"
	"dsh-mobile-ustc/services/remote/internal/store"
	"github.com/coder/websocket"
)

func TestRuntimeRevocationClosesItsHostAndEveryPhoneButPreservesSiblingProfiles(t *testing.T) {
	key := relayTestKey(t)
	jwk, proof := relayTestPublicJWK(t, key)
	const installation = "11111111-1111-4111-8111-111111111111"
	const runtime = "33333333-3333-4333-8333-333333333333"
	const other = "66666666-6666-4666-8666-666666666666"
	fake := &relayTestStore{hostCredential: store.HostCredentialIdentity{InstallationID: installation, KeyThumbprint: proof, PublicJWK: jwk, KeyVersion: 1, ExpiresAt: time.Now().Add(time.Minute)}, detached: make(chan store.RuntimeConnection, 8)}
	relay := New(fake)
	metrics := observability.New()
	relay.ConfigureMetrics(metrics)
	server := httptest.NewServer(relay)
	t.Cleanup(server.Close)
	addHost := func(id, epoch string) *websocket.Conn {
		connection := dialRelayHost(t, server.URL, key, installation, id, epoch)
		t.Cleanup(func() { _ = connection.CloseNow() })
		writeEnvelope(t, connection, "ping", map[string]any{})
		if readEnvelope(t, connection).Type != "pong" {
			t.Fatal("host did not finish admission")
		}
		return connection
	}
	host := addHost(runtime, "aaaaaaaa-1111-4111-8111-111111111111")
	siblingHost := addHost(other, "bbbbbbbb-1111-4111-8111-111111111111")
	addPhone := func(id, device string) *websocket.Conn {
		ticket := store.TicketRedemption{UserID: "22222222-2222-4222-8222-222222222222", DeviceID: device, RuntimeID: id, DeviceKeyVersion: 1, ProofPublicJWK: jwk, ProofKeyThumbprint: proof, GrantVersion: 1, ExpiresAt: time.Now().Add(time.Minute)}
		fake.mu.Lock()
		fake.ticket = ticket
		fake.mu.Unlock()
		connection := dialRelayDevice(t, server.URL, key, ticket, id)
		t.Cleanup(func() { _ = connection.CloseNow() })
		writeEnvelope(t, connection, "ping", map[string]any{})
		if readEnvelope(t, connection).Type != "pong" {
			t.Fatal("phone did not finish admission")
		}
		return connection
	}
	phone := addPhone(runtime, "44444444-4444-4444-8444-444444444444")
	secondPhone := addPhone(runtime, "55555555-5555-4555-8555-555555555555")
	siblingPhone := addPhone(other, "77777777-7777-4777-8777-777777777777")
	for range 2 {
		if err := relay.ApplyControlEvent(context.Background(), store.ControlEvent{Topic: "runtime.revoked", RuntimeID: runtime}); err != nil {
			t.Fatal(err)
		}
	}
	for _, connection := range []*websocket.Conn{host, phone, secondPhone} {
		assertRevokedSocket(t, connection, "access.revoked")
	}
	if err := relay.ApplyControlEvent(context.Background(), store.ControlEvent{Topic: "runtime.revoked", RuntimeID: "invalid"}); !errors.Is(err, store.ErrGrantInvalid) {
		t.Fatal("invalid event was accepted", err)
	}
	// These peers already sent an admission-barrier heartbeat. Preserve the
	// production one-second minimum before checking their continued usability.
	time.Sleep(1010 * time.Millisecond)
	for _, connection := range []*websocket.Conn{siblingHost, siblingPhone} {
		writeEnvelope(t, connection, "ping", map[string]any{})
		if frame := readEnvelope(t, connection); frame.Type != "pong" {
			t.Fatalf("sibling profile heartbeat was not preserved: %+v", frame)
		}
	}
	if metricValue(t, metricsSnapshot(t, metrics), "relay_revoked_connections_total", map[string]string{"role": "installation", "reason": "access_revoked"}) != 1 || metricValue(t, metricsSnapshot(t, metrics), "relay_revoked_connections_total", map[string]string{"role": "device", "reason": "access_revoked"}) != 2 {
		t.Fatal("replayed runtime event changed revocation counts")
	}
}
