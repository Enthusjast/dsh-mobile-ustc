package relay

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/store"
	"github.com/coder/websocket"
)

func TestControlEventsInvalidateOnlyTheirDeviceOrOlderRuntimeGrant(t *testing.T) {
	for _, topic := range []string{"device.revoked", "runtime_grant.updated", "runtime_grant.revoked"} {
		t.Run(topic, func(t *testing.T) {
			key := relayTestKey(t)
			jwk, thumbprint := relayTestPublicJWK(t, key)
			const runtimeID = "33333333-3333-4333-8333-333333333333"
			base := store.TicketRedemption{UserID: "11111111-1111-4111-8111-111111111111", DeviceID: "22222222-2222-4222-8222-222222222222", RuntimeID: runtimeID,
				DeviceKeyVersion: 1, ProofPublicJWK: jwk, ProofKeyThumbprint: thumbprint, GrantVersion: 1, ExpiresAt: time.Now().Add(time.Minute)}
			fake := &relayTestStore{}
			relayServer := New(fake)
			server := httptest.NewServer(relayServer)
			t.Cleanup(server.Close)
			add := func(ticket store.TicketRedemption) *websocket.Conn {
				fake.mu.Lock()
				fake.ticket = ticket
				fake.mu.Unlock()
				connection := dialRelayDevice(t, server.URL, key, ticket, ticket.RuntimeID)
				t.Cleanup(func() { _ = connection.CloseNow() })
				// hello.ok precedes binding; a completed heartbeat proves admission.
				writeEnvelope(t, connection, "ping", map[string]any{})
				if frame := readEnvelope(t, connection); frame.Type != "pong" {
					t.Fatalf("heartbeat=%+v", frame)
				}
				return connection
			}
			old, sibling := add(base), add(base)
			fresh := base
			fresh.GrantVersion = 2
			fresh.DeviceID = "44444444-4444-4444-8444-444444444444"
			add(fresh)
			otherUser := fresh
			otherUser.GrantVersion = 1
			otherUser.UserID = "55555555-5555-4555-8555-555555555555"
			add(otherUser)
			otherRuntime := fresh
			otherRuntime.GrantVersion = 1
			otherRuntime.RuntimeID = "66666666-6666-4666-8666-666666666666"
			add(otherRuntime)
			event := store.ControlEvent{Topic: topic, DeviceID: base.DeviceID, RuntimeID: base.RuntimeID, UserID: base.UserID, GrantVersion: 2}
			for range 2 {
				if err := relayServer.ApplyControlEvent(context.Background(), event); err != nil {
					t.Fatal(err)
				}
			}
			for _, connection := range []*websocket.Conn{old, sibling} {
				assertRevokedSocket(t, connection, "access.revoked")
			}
			relayServer.mu.Lock()
			remaining := 0
			for _, live := range relayServer.connections {
				if !live.closing {
					remaining++
				}
			}
			relayServer.mu.Unlock()
			if remaining != 3 {
				t.Fatalf("unrelated or fresh connections were invalidated: remaining=%d", remaining)
			}
		})
	}
}

type connectionLeaseFixture struct {
	*relayTestStore
	check func(context.Context, []store.RealtimeConnectionLease) ([]string, error)
}

func (fake connectionLeaseFixture) InvalidRealtimeConnectionLeases(ctx context.Context, leases []store.RealtimeConnectionLease) ([]string, error) {
	return fake.check(ctx, leases)
}

func TestAuthoritativeLeaseChecksCloseInvalidAndUnavailableConnections(t *testing.T) {
	for _, scenario := range []string{"device", "installation", "database-unavailable", "deadline"} {
		t.Run(scenario, func(t *testing.T) {
			key := relayTestKey(t)
			jwk, thumbprint := relayTestPublicJWK(t, key)
			const installationID = "11111111-1111-4111-8111-111111111111"
			const runtimeID = "33333333-3333-4333-8333-333333333333"
			fake := &relayTestStore{
				ticket:         store.TicketRedemption{UserID: installationID, DeviceID: "22222222-2222-4222-8222-222222222222", RuntimeID: runtimeID, DeviceKeyVersion: 3, GrantVersion: 7, ProofPublicJWK: jwk, ProofKeyThumbprint: thumbprint, ExpiresAt: time.Now().Add(time.Minute)},
				hostCredential: store.HostCredentialIdentity{InstallationID: installationID, KeyVersion: 2, PublicJWK: jwk, KeyThumbprint: thumbprint, ExpiresAt: time.Now().Add(time.Minute)},
				detached:       make(chan store.RuntimeConnection, 1),
			}
			repository := connectionLeaseFixture{relayTestStore: fake, check: func(ctx context.Context, leases []store.RealtimeConnectionLease) ([]string, error) {
				if len(leases) != 2 {
					t.Fatalf("checked %d leases, want both idle peers", len(leases))
				}
				if scenario == "database-unavailable" {
					return nil, store.ErrDatabaseUnavailable
				}
				if scenario == "deadline" {
					<-ctx.Done()
					return nil, ctx.Err()
				}
				for _, lease := range leases {
					if lease.Role == "device" && (lease.GrantVersion != 7 || lease.DeviceKeyVersion != 3 || lease.ProofKeyThumbprint != thumbprint || lease.UserID == nil || lease.DeviceID == nil) {
						t.Fatalf("device binding lost: %+v", lease)
					}
					if lease.Role == "installation" && (lease.KeyVersion != 2 || lease.InstallationID == nil || lease.RuntimeEpoch == nil) {
						t.Fatalf("host binding lost: %+v", lease)
					}
					if lease.Role == scenario {
						return []string{lease.ConnectionID}, nil
					}
				}
				t.Fatal("missing checked role")
				return nil, nil
			}}
			relayServer := New(repository)
			server := httptest.NewServer(relayServer)
			t.Cleanup(server.Close)
			host := dialRelayHost(t, server.URL, key, installationID, runtimeID, "44444444-4444-4444-8444-444444444444")
			defer host.CloseNow()
			device := dialRelayDevice(t, server.URL, key, fake.ticket, runtimeID)
			defer device.CloseNow()
			for _, connection := range []*websocket.Conn{host, device} {
				writeEnvelope(t, connection, "ping", map[string]any{})
				if frame := readEnvelope(t, connection); frame.Type != "pong" {
					t.Fatalf("heartbeat=%+v", frame)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
			defer cancel()
			err := relayServer.RevalidateConnections(ctx)
			code := "access.revoked"
			if scenario == "database-unavailable" || scenario == "deadline" {
				if !errors.Is(err, store.ErrDatabaseUnavailable) && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("lost validation error: %v", err)
				}
				code = "internal"
			} else if err != nil {
				t.Fatal(err)
			}
			if scenario != "installation" {
				assertRevokedSocket(t, device, code)
			}
			if scenario != "device" {
				assertRevokedSocket(t, host, code)
			}
			if scenario == "installation" && relayServer.hostForRuntime(runtimeID) != nil {
				t.Fatal("invalid host still routable")
			}
		})
	}
}

func assertRevokedSocket(t *testing.T, connection *websocket.Conn, code string) {
	t.Helper()
	if frame := readEnvelope(t, connection); frame.Type != "access.revoked" || frame.Payload["code"] != code {
		t.Fatalf("revocation=%+v, want %s", frame, code)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, _, err := connection.Read(ctx); err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("revoked socket remained open: %v", err)
	}
}

func TestLeaseValidationBatchesEveryAuthenticatedConnection(t *testing.T) {
	seen := make(map[string]bool)
	sizes := []int{}
	repository := connectionLeaseFixture{relayTestStore: &relayTestStore{}, check: func(_ context.Context, leases []store.RealtimeConnectionLease) ([]string, error) {
		sizes = append(sizes, len(leases))
		for _, lease := range leases {
			if seen[lease.ConnectionID] {
				t.Fatalf("duplicate lease check: %s", lease.ConnectionID)
			}
			seen[lease.ConnectionID] = true
		}
		return nil, nil
	}}
	server := New(repository)
	for index := range 257 {
		conn := &websocket.Conn{}
		server.connections[conn] = &liveConnection{conn: conn, peer: peer{role: "device"}, connectionID: fmt.Sprintf("%08x-1111-4111-8111-111111111111", index+1)}
	}
	// Neither a pending handshake nor an already closing peer is a live lease.
	server.connections[&websocket.Conn{}] = &liveConnection{}
	server.connections[&websocket.Conn{}] = &liveConnection{connectionID: "closing", closing: true}
	if err := server.RevalidateConnections(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 257 || len(sizes) != 3 || sizes[0] != 128 || sizes[1] != 128 || sizes[2] != 1 {
		t.Fatalf("incomplete or unbounded lease checks: seen=%d batches=%v", len(seen), sizes)
	}
}
