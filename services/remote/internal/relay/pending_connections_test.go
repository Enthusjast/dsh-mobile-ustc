package relay

import (
	"context"
	"github.com/coder/websocket"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/store"
)

func TestPendingHandshakeBudgetIsSeparateFromAuthenticatedConnections(t *testing.T) {
	key := relayTestKey(t)
	jwk, jkt := relayTestPublicJWK(t, key)
	const installation = "11111111-1111-4111-8111-111111111111"
	const runtime = "33333333-3333-4333-8333-333333333333"
	fake := &relayTestStore{hostCredential: store.HostCredentialIdentity{InstallationID: installation, KeyVersion: 1, PublicJWK: jwk, KeyThumbprint: jkt, ExpiresAt: time.Now().Add(time.Minute)}, detached: make(chan store.RuntimeConnection, 2)}
	relay := New(fake)
	if err := relay.ConfigurePendingHandshakes(1); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(relay)
	defer server.Close()
	dial := func() *websocket.Conn {
		t.Helper()
		connection, _, err := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(server.URL, "http")+"/v1/realtime", &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"DSH-Host " + strings.Repeat("H", 43)}}, Subprotocols: []string{protocolName}})
		if err != nil {
			t.Fatal(err)
		}
		return connection
	}
	// A fully proved Host no longer occupies the pending reservation.
	host := dialRelayHost(t, server.URL, key, installation, runtime, "44444444-4444-4444-8444-444444444444")
	defer host.CloseNow()
	pending := dial()
	defer pending.CloseNow()
	if frame := readEnvelope(t, pending); frame.Type != "challenge" {
		t.Fatal("pending handshake was not accepted", frame)
	}
	if err := relay.ConfigurePendingHandshakes(2); err == nil {
		t.Fatal("live pending budget was reconfigured")
	}
	blocked := dial()
	defer blocked.CloseNow()
	// This transport never gets a challenge or registered writer reservation.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, _, err := blocked.Read(ctx); err == nil {
		t.Fatal("pending handshake cap was bypassed")
	}
	_ = pending.CloseNow()
	metricUntil(t, func() bool { relay.mu.Lock(); defer relay.mu.Unlock(); return len(relay.connections) == 1 })
	probe := dial()
	defer probe.CloseNow()
	if frame := readEnvelope(t, probe); frame.Type != "challenge" {
		t.Fatal("released pending capacity unavailable", frame)
	}
}
