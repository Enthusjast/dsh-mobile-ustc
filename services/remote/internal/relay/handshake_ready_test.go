package relay

import (
	"net/http/httptest"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/store"
)

func TestHelloOKAlreadyPublishesBothRoutesAndNegotiatedCapabilities(t *testing.T) {
	for range 16 {
		func() {
			key := relayTestKey(t)
			jwk, thumbprint := relayTestPublicJWK(t, key)
			const runtime = "33333333-3333-4333-8333-333333333333"
			const installation = "11111111-1111-4111-8111-111111111111"
			const epoch = "44444444-4444-4444-8444-444444444444"
			fake := &relayTestStore{
				ticket: store.TicketRedemption{UserID: installation, DeviceID: "22222222-2222-4222-8222-222222222222", RuntimeID: runtime,
					DeviceKeyVersion: 1, GrantVersion: 1, ProofPublicJWK: jwk, ProofKeyThumbprint: thumbprint, ExpiresAt: time.Now().Add(time.Minute),
					Scope: store.GrantScope{Actions: []string{"session.read"}, Sessions: []string{}, Workspaces: []string{}}},
				hostCredential: store.HostCredentialIdentity{InstallationID: installation, KeyVersion: 1, PublicJWK: jwk, KeyThumbprint: thumbprint, ExpiresAt: time.Now().Add(time.Minute)},
				detached:       make(chan store.RuntimeConnection, 1),
			}
			relay := New(fake)
			server := httptest.NewServer(relay)
			defer server.Close()
			host := dialRelayHost(t, server.URL, key, installation, runtime, epoch)
			defer host.CloseNow()
			if live := relay.hostForRuntime(runtime); live == nil || live.runtimeEpoch != epoch || !live.supports("session.read.v1") {
				t.Fatal("host received hello.ok before its route and capabilities became available")
			}
			device := dialRelayDevice(t, server.URL, key, fake.ticket, runtime)
			defer device.CloseNow()
			relay.mu.Lock()
			ready := false
			for live := range relay.devices[runtime][fake.ticket.DeviceID] {
				ready = ready || live.connectionID != "" && live.supports("session.read.v1")
			}
			relay.mu.Unlock()
			if !ready {
				t.Fatal("device received hello.ok before its route and capabilities became available")
			}
		}()
	}
}
