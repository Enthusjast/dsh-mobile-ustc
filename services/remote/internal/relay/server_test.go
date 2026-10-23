package relay

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/store"
	"github.com/coder/websocket"
)

type relayTestStore struct {
	mu                 sync.Mutex
	ticket             store.TicketRedemption
	ticketErr          error
	ticketPrepareCalls int
	ticketConsumeCalls int
	hostCredential     store.HostCredentialIdentity
	hostErr            error
	attached           store.RuntimeConnection
	attachInput        store.RuntimeConnectionInput
	attachErr          error
	touchCalls         int
	detached           chan store.RuntimeConnection
	commands           map[string]store.CommandStatus
	leaseCalls         int
	leaseErr           error
}

func (fake *relayTestStore) PrepareRealtimeTicket(context.Context, string) (store.TicketRedemption, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.ticketPrepareCalls++
	return fake.ticket, fake.ticketErr
}

func (fake *relayTestStore) ConsumeRealtimeTicket(context.Context, string) (store.TicketRedemption, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.ticketConsumeCalls++
	return fake.ticket, fake.ticketErr
}

func (fake *relayTestStore) ValidateRealtimeLease(context.Context, store.TicketRedemption) error {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.leaseCalls++
	return fake.leaseErr
}

func (fake *relayTestStore) LookupHostConnectionCredential(context.Context, string) (store.HostCredentialIdentity, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return fake.hostCredential, fake.hostErr
}

func (fake *relayTestStore) AttachRuntimeConnection(_ context.Context, input store.RuntimeConnectionInput) (store.RuntimeConnection, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.attachInput = input
	if fake.attachErr != nil {
		return store.RuntimeConnection{}, fake.attachErr
	}
	fake.attached = store.RuntimeConnection{
		InstallationID: input.InstallationID, RuntimeID: input.RuntimeID, RuntimeEpoch: input.RuntimeEpoch,
		ConnectionID: input.ConnectionID, ProtocolVersion: input.ProtocolVersion,
	}
	return fake.attached, nil
}

func (fake *relayTestStore) TouchRuntimeConnection(context.Context, string, string, string, string) error {
	fake.mu.Lock()
	fake.touchCalls++
	fake.mu.Unlock()
	return nil
}

func (fake *relayTestStore) DetachRuntimeConnection(_ context.Context, installationID, runtimeID, runtimeEpoch, connectionID string) error {
	fake.detached <- store.RuntimeConnection{
		InstallationID: installationID, RuntimeID: runtimeID, RuntimeEpoch: runtimeEpoch,
		ConnectionID: connectionID,
	}
	return nil
}

func (fake *relayTestStore) RecordRealtimeCommand(_ context.Context, _ store.TicketRedemption, requestID, sessionID, digest string) (store.CommandStatus, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if !slices.Contains(fake.ticket.Scope.Actions, "message.submit") || !slices.Contains(fake.ticket.Scope.Sessions, sessionID) {
		return store.CommandStatus{}, store.ErrAccessDenied
	}
	if fake.commands == nil {
		fake.commands = make(map[string]store.CommandStatus)
	}
	if previous, ok := fake.commands[requestID]; ok {
		if previous.SessionID != sessionID || previous.PayloadSHA256 != digest {
			return store.CommandStatus{}, store.ErrCommandConflict
		}
		return previous, nil
	}
	status := store.CommandStatus{RequestID: requestID, SessionID: sessionID, State: "received", PayloadSHA256: digest, UpdatedAt: time.Now()}
	fake.commands[requestID] = status
	return status, nil
}

func (fake *relayTestStore) RecordRealtimeCommandReceipt(_ context.Context, receipt store.RelayCommandReceipt) (store.CommandStatus, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	status, ok := fake.commands[receipt.RequestID]
	if !ok || status.SessionID != receipt.SessionID || status.PayloadSHA256 != receipt.PayloadSHA256 {
		return store.CommandStatus{}, store.ErrCommandTransition
	}
	status.State = receipt.State
	status.UpdatedAt = time.Now()
	fake.commands[receipt.RequestID] = status
	return status, nil
}

func (fake *relayTestStore) MarkRealtimeCommandUnknown(_ context.Context, _ store.TicketRedemption, requestID, sessionID, digest string) (store.CommandStatus, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	status, ok := fake.commands[requestID]
	if !ok || status.SessionID != sessionID || status.PayloadSHA256 != digest {
		return store.CommandStatus{}, store.ErrCommandTransition
	}
	status.State = "outcome_unknown"
	status.UpdatedAt = time.Now()
	fake.commands[requestID] = status
	return status, nil
}

func TestDeviceTicketRequiresKeyProofBeforeHelloAndHeartbeat(t *testing.T) {
	key := relayTestKey(t)
	publicJWK, thumbprint := relayTestPublicJWK(t, key)
	fake := &relayTestStore{ticket: store.TicketRedemption{
		UserID: "11111111-1111-4111-8111-111111111111", DeviceID: "22222222-2222-4222-8222-222222222222",
		DeviceKeyVersion: 1, ProofKeyThumbprint: thumbprint, ProofPublicJWK: publicJWK,
		RuntimeID: "33333333-3333-4333-8333-333333333333", GrantVersion: 4,
		Scope:     store.GrantScope{Actions: []string{"session.list"}, Workspaces: []string{}, Sessions: []string{}},
		ExpiresAt: time.Now().Add(30 * time.Second),
	}}
	relayServer := New(fake)
	server := httptest.NewServer(relayServer)
	t.Cleanup(server.Close)
	connection, response, err := websocket.Dial(context.Background(), wsURL(server.URL), &websocket.DialOptions{
		HTTPHeader:   http.Header{"Authorization": []string{"DSH-Ticket " + strings.Repeat("A", 43)}},
		Subprotocols: []string{protocolName},
	})
	if err != nil {
		t.Fatalf("dial realtime socket: response=%v error=%v", response, err)
	}
	t.Cleanup(func() { _ = connection.Close(websocket.StatusNormalClosure, "test complete") })
	if connection.Subprotocol() != protocolName {
		t.Fatalf("subprotocol=%q, want %q", connection.Subprotocol(), protocolName)
	}
	challenge := readChallenge(t, connection, "device")
	deviceHello := deviceHandshakePayload{
		DeviceID: fake.ticket.DeviceID, Protocols: []int{1}, Capabilities: []string{"connection.heartbeat.v1"},
	}
	normalizedDeviceHello, err := normalizeDeviceHello(deviceHello, fake.ticket.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	helloDigest := normalizedDeviceHello.digest()
	proof := relaySign(t, key, map[string]any{
		"iss": fake.ticket.DeviceID, "aud": auth.RelayHandshakeAudience,
		"challenge_id": challenge.ChallengeID, "connection_id": challenge.ConnectionID,
		"nonce": challenge.Nonce, "runtime_id": fake.ticket.RuntimeID, "hello_sha256": helloDigest,
		"iat": time.Now().Unix(), "jti": "device-relay-proof-jti-00000001",
	})
	deviceHello.Proof = proof
	writeEnvelope(t, connection, "hello.proof", deviceHello)
	hello := readEnvelope(t, connection)
	if hello.Type != "hello.ok" || hello.Payload["role"] != "device" || hello.Payload["device_id"] != fake.ticket.DeviceID || hello.Payload["connection_id"] != challenge.ConnectionID {
		t.Fatalf("unexpected device hello response: %+v", hello)
	}
	fake.mu.Lock()
	preparedCalls, consumedCalls := fake.ticketPrepareCalls, fake.ticketConsumeCalls
	fake.mu.Unlock()
	if preparedCalls != 1 || consumedCalls != 1 {
		t.Fatalf("ticket prepare/consume calls=%d/%d, want 1/1", preparedCalls, consumedCalls)
	}
	writeEnvelope(t, connection, "ping", map[string]any{})
	pong := readEnvelope(t, connection)
	if pong.Type != "pong" || pong.Payload["connection_id"] != challenge.ConnectionID {
		t.Fatalf("unexpected heartbeat response: %+v", pong)
	}
	writeEnvelope(t, connection, "ping", map[string]any{})
	rateError := readEnvelope(t, connection)
	if rateError.Type != "error" || rateError.Payload["code"] != "rate.limited" {
		t.Fatalf("rapid heartbeat was not rate limited: %+v", rateError)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, _, err := connection.Read(ctx); err == nil {
		t.Fatal("connection remained open after heartbeat rate limit")
	}
}

func TestInvalidDeviceProofDoesNotConsumeTicket(t *testing.T) {
	key := relayTestKey(t)
	publicJWK, thumbprint := relayTestPublicJWK(t, key)
	fake := &relayTestStore{ticket: store.TicketRedemption{
		DeviceID: "22222222-2222-4222-8222-222222222222", ProofKeyThumbprint: thumbprint,
		ProofPublicJWK: publicJWK, RuntimeID: "33333333-3333-4333-8333-333333333333",
		ExpiresAt: time.Now().Add(30 * time.Second),
	}}
	relayServer := New(fake)
	server := httptest.NewServer(relayServer)
	t.Cleanup(server.Close)
	connection, _, err := websocket.Dial(context.Background(), wsURL(server.URL), &websocket.DialOptions{
		HTTPHeader:   http.Header{"Authorization": []string{"DSH-Ticket " + strings.Repeat("B", 43)}},
		Subprotocols: []string{protocolName},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(websocket.StatusNormalClosure, "test complete")
	challenge := readChallenge(t, connection, "device")
	wrongKey := relayTestKey(t)
	deviceHello := deviceHandshakePayload{
		DeviceID: fake.ticket.DeviceID, Protocols: []int{1}, Capabilities: []string{},
	}
	normalizedDeviceHello, err := normalizeDeviceHello(deviceHello, fake.ticket.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	helloDigest := normalizedDeviceHello.digest()
	proof := relaySign(t, wrongKey, map[string]any{
		"iss": fake.ticket.DeviceID, "aud": auth.RelayHandshakeAudience,
		"challenge_id": challenge.ChallengeID, "connection_id": challenge.ConnectionID,
		"nonce": challenge.Nonce, "runtime_id": fake.ticket.RuntimeID, "hello_sha256": helloDigest,
		"iat": time.Now().Unix(), "jti": "device-relay-proof-jti-00000002",
	})
	deviceHello.Proof = proof
	writeEnvelope(t, connection, "hello.proof", deviceHello)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, _, err := connection.Read(ctx); err == nil {
		t.Fatal("invalid key proof received a server frame")
	}
	fake.mu.Lock()
	consumedCalls := fake.ticketConsumeCalls
	fake.mu.Unlock()
	if consumedCalls != 0 {
		t.Fatal("invalid device proof consumed the one-use ticket")
	}
}

func TestHostHandshakeBindsHelloAndPersistsRuntimeConnection(t *testing.T) {
	key := relayTestKey(t)
	publicJWK, thumbprint := relayTestPublicJWK(t, key)
	installationID := "11111111-1111-4111-8111-111111111111"
	fake := &relayTestStore{
		hostCredential: store.HostCredentialIdentity{
			InstallationID: installationID, KeyThumbprint: thumbprint, PublicJWK: publicJWK,
			KeyVersion: 2, ExpiresAt: time.Now().Add(5 * time.Minute),
		},
		detached: make(chan store.RuntimeConnection, 1),
	}
	relayServer := New(fake)
	server := httptest.NewServer(relayServer)
	t.Cleanup(server.Close)
	connection, _, err := websocket.Dial(context.Background(), wsURL(server.URL), &websocket.DialOptions{
		HTTPHeader:   http.Header{"Authorization": []string{"DSH-Host " + strings.Repeat("C", 43)}},
		Subprotocols: []string{protocolName},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close(websocket.StatusNormalClosure, "test complete") })
	challenge := readChallenge(t, connection, "installation")
	hello := hostHandshakePayload{
		RuntimeID: "33333333-3333-4333-8333-333333333333", RuntimeEpoch: "44444444-4444-4444-8444-444444444444",
		DSHVersion: "0.2.1-rc.2", ApplicationVersion: "1.0.0", PluginVersion: "0.1.0",
		ProtocolVersion: 1, Capabilities: []string{"connection.heartbeat.v1", "unknown.capability"},
	}
	normalized, err := normalizeHostHello(hello)
	if err != nil {
		t.Fatal(err)
	}
	proofDigest := normalized.digest()
	proof := relaySign(t, key, map[string]any{
		"iss": installationID, "aud": auth.RelayHandshakeAudience,
		"challenge_id": challenge.ChallengeID, "connection_id": challenge.ConnectionID,
		"nonce": challenge.Nonce, "runtime_id": normalized.RuntimeID,
		"runtime_epoch": normalized.RuntimeEpoch, "hello_sha256": proofDigest,
		"iat": time.Now().Unix(), "jti": "host-relay-proof-jti-000000001",
	})
	hello.Proof = proof
	writeEnvelope(t, connection, "hello.proof", hello)
	ack := readEnvelope(t, connection)
	if ack.Type != "hello.ok" || ack.Payload["role"] != "host" || ack.Payload["installation_id"] != installationID ||
		ack.Payload["runtime_id"] != normalized.RuntimeID {
		t.Fatalf("unexpected host hello response: %+v", ack)
	}
	fake.mu.Lock()
	attached := fake.attachInput
	fake.mu.Unlock()
	if attached.InstallationID != installationID || attached.KeyVersion != 2 || attached.RuntimeEpoch != normalized.RuntimeEpoch || attached.ConnectionID != challenge.ConnectionID {
		t.Fatalf("host hello was not persisted: %+v", attached)
	}
	writeEnvelope(t, connection, "ping", map[string]any{})
	if pong := readEnvelope(t, connection); pong.Type != "pong" {
		t.Fatalf("unexpected heartbeat: %+v", pong)
	}
	fake.mu.Lock()
	touchCalls := fake.touchCalls
	fake.mu.Unlock()
	if touchCalls != 1 {
		t.Fatalf("runtime heartbeat updates=%d, want 1", touchCalls)
	}
	drainCtx, cancelDrain := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelDrain()
	if err := relayServer.Drain(drainCtx); err != nil {
		t.Fatalf("drain realtime sockets: %v", err)
	}
	if frame := readEnvelope(t, connection); frame.Type != "server.draining" {
		t.Fatalf("drain frame type=%q, want server.draining", frame.Type)
	}
	if _, _, err := connection.Read(drainCtx); err == nil {
		t.Fatal("connection remained open after Relay drain")
	}
	select {
	case detached := <-fake.detached:
		if detached.ConnectionID != challenge.ConnectionID {
			t.Fatalf("detached connection=%+v", detached)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("host runtime connection did not detach")
	}
}

func TestMessageSubmitRoutesToHostAndPersistsCommandReceipts(t *testing.T) {
	deviceKey := relayTestKey(t)
	deviceJWK, deviceThumbprint := relayTestPublicJWK(t, deviceKey)
	hostKey := relayTestKey(t)
	hostJWK, hostThumbprint := relayTestPublicJWK(t, hostKey)
	const (
		deviceID       = "22222222-2222-4222-8222-222222222222"
		installationID = "11111111-1111-4111-8111-111111111111"
		runtimeID      = "33333333-3333-4333-8333-333333333333"
		runtimeEpoch   = "44444444-4444-4444-8444-444444444444"
		sessionID      = "55555555-5555-4555-8555-555555555555"
		requestID      = "66666666-6666-4666-8666-666666666666"
	)
	fake := &relayTestStore{
		ticket: store.TicketRedemption{
			UserID: "77777777-7777-4777-8777-777777777777", DeviceID: deviceID,
			DeviceKeyVersion: 1, ProofKeyThumbprint: deviceThumbprint, ProofPublicJWK: deviceJWK,
			RuntimeID: runtimeID, GrantVersion: 2,
			Scope:     store.GrantScope{Actions: []string{"message.submit"}, Workspaces: []string{}, Sessions: []string{sessionID}},
			ExpiresAt: time.Now().Add(30 * time.Second),
		},
		hostCredential: store.HostCredentialIdentity{
			InstallationID: installationID, KeyThumbprint: hostThumbprint, PublicJWK: hostJWK,
			KeyVersion: 1, ExpiresAt: time.Now().Add(5 * time.Minute),
		},
		detached: make(chan store.RuntimeConnection, 1),
	}
	server := httptest.NewServer(New(fake))
	t.Cleanup(server.Close)
	hostConnection := dialRelayHost(t, server.URL, hostKey, installationID, runtimeID, runtimeEpoch)
	t.Cleanup(func() { _ = hostConnection.CloseNow() })
	deviceConnection := dialRelayDevice(t, server.URL, deviceKey, fake.ticket, runtimeID)
	t.Cleanup(func() { _ = deviceConnection.CloseNow() })

	payload := messageSubmitPayload{Mode: "queue", Content: []messageContent{{Type: "text", Text: "continue the current task"}}}
	digest, err := messageSubmitDigest(sessionID, payload)
	if err != nil {
		t.Fatal(err)
	}
	submit := map[string]any{
		"v": 1, "type": "message.submit", "request_id": requestID,
		"runtime_id": runtimeID, "session_id": sessionID, "payload": payload,
	}
	writeWireFrame(t, deviceConnection, submit)
	forwarded := readEnvelope(t, hostConnection)
	if forwarded.Type != "message.submit" || forwarded.RequestID != requestID ||
		forwarded.RuntimeID != runtimeID || forwarded.SessionID != sessionID ||
		forwarded.DeviceID != deviceID || forwarded.UserID != fake.ticket.UserID ||
		forwarded.PayloadSHA256 != digest {
		t.Fatalf("invalid host command frame: %+v", forwarded)
	}
	if received := readEnvelope(t, deviceConnection); received.Type != "command.receipt" || received.Payload["state"] != "received" {
		t.Fatalf("expected transient received receipt, got %+v", received)
	}

	writeWireFrame(t, hostConnection, map[string]any{
		"v": 1, "type": "command.receipt", "request_id": requestID,
		"runtime_id": runtimeID, "runtime_epoch": runtimeEpoch, "session_id": sessionID,
		"device_id": deviceID,
		"payload":   map[string]any{"state": "host_accepted", "payload_sha256": digest},
	})
	accepted := readEnvelope(t, deviceConnection)
	if accepted.Type != "command.receipt" || accepted.Payload["state"] != "host_accepted" ||
		accepted.Payload["payload_sha256"] != digest {
		t.Fatalf("host receipt did not reach the originating device: %+v", accepted)
	}

	writeWireFrame(t, deviceConnection, submit)
	duplicate := readEnvelope(t, deviceConnection)
	if duplicate.Type != "command.receipt" || duplicate.Payload["state"] != "host_accepted" {
		t.Fatalf("idempotent retry did not return stored status: %+v", duplicate)
	}
	conflictPayload := messageSubmitPayload{Mode: "queue", Content: []messageContent{{Type: "text", Text: "different body"}}}
	writeWireFrame(t, deviceConnection, map[string]any{
		"v": 1, "type": "message.submit", "request_id": requestID,
		"runtime_id": runtimeID, "session_id": sessionID, "payload": conflictPayload,
	})
	conflict := readEnvelope(t, deviceConnection)
	if conflict.Type != "error" || conflict.Payload["code"] != "command.request_conflict" {
		t.Fatalf("same request ID with different content was not rejected: %+v", conflict)
	}
	writeWireFrame(t, deviceConnection, map[string]any{
		"v": 1, "type": "message.submit", "request_id": "88888888-8888-4888-8888-888888888888",
		"runtime_id": runtimeID, "session_id": "99999999-9999-4999-8999-999999999999", "payload": payload,
	})
	denied := readEnvelope(t, deviceConnection)
	if denied.Type != "error" || denied.Payload["code"] != "access.denied" {
		t.Fatalf("out-of-scope session was not denied: %+v", denied)
	}
	fake.mu.Lock()
	leaseCalls := fake.leaseCalls
	fake.leaseErr = store.ErrTicketInvalid
	fake.mu.Unlock()
	if leaseCalls < 3 {
		t.Fatalf("active device lease was not rechecked before scoped receipts: %d checks", leaseCalls)
	}
	writeWireFrame(t, hostConnection, map[string]any{
		"v": 1, "type": "command.receipt", "request_id": requestID,
		"runtime_id": runtimeID, "runtime_epoch": runtimeEpoch, "session_id": sessionID,
		"device_id": deviceID,
		"payload":   map[string]any{"state": "agent_queued", "payload_sha256": digest},
	})
	revoked := readEnvelope(t, deviceConnection)
	if revoked.Type != "access.revoked" {
		t.Fatalf("revoked device received scoped command data: %+v", revoked)
	}
}

func dialRelayHost(t *testing.T, serverURL string, key *ecdsa.PrivateKey, installationID, runtimeID, runtimeEpoch string) *websocket.Conn {
	t.Helper()
	connection, _, err := websocket.Dial(context.Background(), wsURL(serverURL), &websocket.DialOptions{
		HTTPHeader:   http.Header{"Authorization": []string{"DSH-Host " + strings.Repeat("H", 43)}},
		Subprotocols: []string{protocolName},
	})
	if err != nil {
		t.Fatal(err)
	}
	challenge := readChallenge(t, connection, "installation")
	hello := hostHandshakePayload{
		RuntimeID: runtimeID, RuntimeEpoch: runtimeEpoch,
		DSHVersion: "0.2.1-rc.2", ApplicationVersion: "1.0.0", PluginVersion: "0.1.0",
		ProtocolVersion: 1, Capabilities: []string{"command.relay.v1", "connection.heartbeat.v1"},
	}
	normalized, err := normalizeHostHello(hello)
	if err != nil {
		t.Fatal(err)
	}
	hello.Proof = relaySign(t, key, map[string]any{
		"iss": installationID, "aud": auth.RelayHandshakeAudience,
		"challenge_id": challenge.ChallengeID, "connection_id": challenge.ConnectionID,
		"nonce": challenge.Nonce, "runtime_id": normalized.RuntimeID,
		"runtime_epoch": normalized.RuntimeEpoch, "hello_sha256": normalized.digest(),
		"iat": time.Now().Unix(), "jti": "host-relay-routing-proof-000001",
	})
	writeEnvelope(t, connection, "hello.proof", hello)
	ack := readEnvelope(t, connection)
	if ack.Type != "hello.ok" || ack.Payload["role"] != "host" || ack.Payload["installation_id"] != installationID {
		t.Fatalf("host socket did not authenticate: %+v", ack)
	}
	return connection
}

func dialRelayDevice(t *testing.T, serverURL string, key *ecdsa.PrivateKey, ticket store.TicketRedemption, runtimeID string) *websocket.Conn {
	t.Helper()
	connection, _, err := websocket.Dial(context.Background(), wsURL(serverURL), &websocket.DialOptions{
		HTTPHeader:   http.Header{"Authorization": []string{"DSH-Ticket " + strings.Repeat("T", 43)}},
		Subprotocols: []string{protocolName},
	})
	if err != nil {
		t.Fatal(err)
	}
	challenge := readChallenge(t, connection, "device")
	hello := deviceHandshakePayload{
		DeviceID: ticket.DeviceID, Protocols: []int{1}, Capabilities: []string{"command.relay.v1", "connection.heartbeat.v1"},
	}
	normalized, err := normalizeDeviceHello(hello, ticket.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	hello.Proof = relaySign(t, key, map[string]any{
		"iss": ticket.DeviceID, "aud": auth.RelayHandshakeAudience,
		"challenge_id": challenge.ChallengeID, "connection_id": challenge.ConnectionID,
		"nonce": challenge.Nonce, "runtime_id": runtimeID, "hello_sha256": normalized.digest(),
		"iat": time.Now().Unix(), "jti": "device-relay-routing-proof-0001",
	})
	writeEnvelope(t, connection, "hello.proof", hello)
	ack := readEnvelope(t, connection)
	if ack.Type != "hello.ok" || ack.Payload["role"] != "device" || ack.Payload["runtime_id"] != runtimeID {
		t.Fatalf("device socket did not authenticate: %+v", ack)
	}
	return connection
}

func writeWireFrame(t *testing.T, connection *websocket.Conn, frame map[string]any) {
	t.Helper()
	data, err := json.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := connection.Write(ctx, websocket.MessageText, data); err != nil {
		t.Fatal(err)
	}
}

func TestRealtimeEndpointRejectsTicketInQuery(t *testing.T) {
	server := httptest.NewServer(New(&relayTestStore{}))
	t.Cleanup(server.Close)
	client := &http.Client{Timeout: 2 * time.Second}
	request, err := http.NewRequest(http.MethodGet, server.URL+"?ticket="+strings.Repeat("D", 43), nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "DSH-Ticket "+strings.Repeat("D", 43))
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("ticket query status=%d, want 400", response.StatusCode)
	}
}

func TestRealtimeEndpointClosesConnectionsWithoutSubprotocol(t *testing.T) {
	key := relayTestKey(t)
	publicJWK, thumbprint := relayTestPublicJWK(t, key)
	fake := &relayTestStore{ticket: store.TicketRedemption{
		DeviceID: "22222222-2222-4222-8222-222222222222", ProofKeyThumbprint: thumbprint,
		ProofPublicJWK: publicJWK, RuntimeID: "33333333-3333-4333-8333-333333333333",
	}}
	server := httptest.NewServer(New(fake))
	t.Cleanup(server.Close)
	connection, _, err := websocket.Dial(context.Background(), wsURL(server.URL), &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{"DSH-Ticket " + strings.Repeat("E", 43)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseNow()
	if connection.Subprotocol() != "" {
		t.Fatalf("unexpected subprotocol=%q", connection.Subprotocol())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, _, err := connection.Read(ctx); err == nil {
		t.Fatal("connection without dsh.remote.v1 remained open")
	}
}

type testChallenge struct {
	ConnectionID string `json:"connection_id"`
	ChallengeID  string `json:"challenge_id"`
	Nonce        string `json:"nonce"`
	Role         string `json:"role"`
}

type testEnvelope struct {
	V             int            `json:"v"`
	Type          string         `json:"type"`
	RequestID     string         `json:"request_id"`
	RuntimeID     string         `json:"runtime_id"`
	RuntimeEpoch  string         `json:"runtime_epoch"`
	SessionID     string         `json:"session_id"`
	DeviceID      string         `json:"device_id"`
	UserID        string         `json:"user_id"`
	PayloadSHA256 string         `json:"payload_sha256"`
	Payload       map[string]any `json:"payload"`
}

func readChallenge(t *testing.T, connection *websocket.Conn, role string) testChallenge {
	t.Helper()
	envelope := readEnvelope(t, connection)
	if envelope.Type != "challenge" {
		t.Fatalf("frame type=%q, want challenge", envelope.Type)
	}
	data, err := json.Marshal(envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var challenge testChallenge
	if err := json.Unmarshal(data, &challenge); err != nil || challenge.Role != role || challenge.Nonce == "" ||
		!uuidPattern.MatchString(challenge.ConnectionID) || !uuidPattern.MatchString(challenge.ChallengeID) {
		t.Fatalf("invalid challenge payload=%s error=%v", data, err)
	}
	return challenge
}

func readEnvelope(t *testing.T, connection *websocket.Conn) testEnvelope {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	messageType, data, err := connection.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if messageType != websocket.MessageText {
		t.Fatalf("message type=%v, want text", messageType)
	}
	var envelope testEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatalf("decode server frame: %v", err)
	}
	return envelope
}

func writeEnvelope(t *testing.T, connection *websocket.Conn, typ string, payload any) {
	t.Helper()
	data, err := json.Marshal(map[string]any{"v": 1, "type": typ, "payload": payload})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := connection.Write(ctx, websocket.MessageText, data); err != nil {
		t.Fatal(err)
	}
}

func relayTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func relayTestPublicJWK(t *testing.T, key *ecdsa.PrivateKey) ([]byte, string) {
	t.Helper()
	jwk := map[string]string{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(key.PublicKey.X.FillBytes(make([]byte, 32))),
		"y": base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.FillBytes(make([]byte, 32))),
	}
	encoded, err := json.Marshal(jwk)
	if err != nil {
		t.Fatal(err)
	}
	thumbprint, err := auth.PublicP256JWKThumbprintJSON(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return encoded, thumbprint
}

func relaySign(t *testing.T, key *ecdsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"typ": "dsh-relay-handshake-proof+jwt", "alg": "ES256"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func wsURL(httpURL string) string {
	return "ws" + strings.TrimPrefix(httpURL, "http")
}
