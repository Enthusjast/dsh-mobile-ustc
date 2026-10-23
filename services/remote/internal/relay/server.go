package relay

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/store"
	"github.com/coder/websocket"
)

const (
	protocolName         = "dsh.remote.v1"
	maxFrameBytes        = 64 << 10
	handshakeTimeout     = 15 * time.Second
	connectionIdleTime   = 45 * time.Second
	deviceConnectionLife = 5 * time.Minute
	closeHandshakeGrace  = 250 * time.Millisecond
	heartbeatSeconds     = 20
)

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var capabilityPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

type Repository interface {
	PrepareRealtimeTicket(context.Context, string) (store.TicketRedemption, error)
	ConsumeRealtimeTicket(context.Context, string) (store.TicketRedemption, error)
	LookupHostConnectionCredential(context.Context, string) (store.HostCredentialIdentity, error)
	AttachRuntimeConnection(context.Context, store.RuntimeConnectionInput) (store.RuntimeConnection, error)
	TouchRuntimeConnection(context.Context, string, string, string, string) error
	DetachRuntimeConnection(context.Context, string, string, string, string) error
}

type Server struct {
	database    Repository
	mu          sync.Mutex
	connections map[*websocket.Conn]struct{}
	active      sync.WaitGroup
	draining    bool
}

type peer struct {
	role         string
	deviceID     string
	ticket       string
	installation store.HostCredentialIdentity
	redemption   store.TicketRedemption
}

type wireEnvelope struct {
	V       int             `json:"v"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

type deviceHandshakePayload struct {
	Proof        string   `json:"proof"`
	DeviceID     string   `json:"device_id"`
	Protocols    []int    `json:"protocols"`
	Capabilities []string `json:"capabilities"`
}

type normalizedDeviceHello struct {
	DeviceID     string   `json:"device_id"`
	Protocols    []int    `json:"protocols"`
	Capabilities []string `json:"capabilities"`
}

type hostHandshakePayload struct {
	Proof              string   `json:"proof"`
	RuntimeID          string   `json:"runtime_id"`
	RuntimeEpoch       string   `json:"runtime_epoch"`
	DSHVersion         string   `json:"dsh_version"`
	ApplicationVersion string   `json:"application_version"`
	PluginVersion      string   `json:"plugin_version"`
	ProtocolVersion    int      `json:"protocol_version"`
	Capabilities       []string `json:"capabilities"`
}

type normalizedHostHello struct {
	RuntimeID          string   `json:"runtime_id"`
	RuntimeEpoch       string   `json:"runtime_epoch"`
	DSHVersion         string   `json:"dsh_version"`
	ApplicationVersion string   `json:"application_version"`
	PluginVersion      string   `json:"plugin_version"`
	ProtocolVersion    int      `json:"protocol_version"`
	Capabilities       []string `json:"capabilities"`
}

func New(database Repository) *Server {
	return &Server{database: database, connections: make(map[*websocket.Conn]struct{})}
}

func (server *Server) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	if request.URL.RawQuery != "" {
		writeError(response, http.StatusBadRequest, "protocol.invalid")
		return
	}
	peer, err := server.authenticateCredential(request)
	if err != nil {
		server.writeAuthenticationError(response, err)
		return
	}
	connection, err := websocket.Accept(response, request, &websocket.AcceptOptions{
		Subprotocols:    []string{protocolName},
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return
	}
	connection.SetReadLimit(maxFrameBytes)
	if !server.registerConnection(connection) {
		closePolicy(connection, "server draining")
		_ = connection.CloseNow()
		return
	}
	defer server.unregisterConnection(connection)
	defer connection.Close(websocket.StatusNormalClosure, "connection closed")
	if connection.Subprotocol() != protocolName {
		closePolicy(connection, "protocol required")
		return
	}
	server.runHandshake(request.Context(), connection, peer)
}

func (server *Server) registerConnection(connection *websocket.Conn) bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.draining {
		return false
	}
	server.active.Add(1)
	server.connections[connection] = struct{}{}
	return true
}

func (server *Server) unregisterConnection(connection *websocket.Conn) {
	server.mu.Lock()
	delete(server.connections, connection)
	server.mu.Unlock()
	server.active.Done()
}

// Drain rejects future sockets, closes current sockets, and waits for their
// runtime cleanup to finish before the caller shuts down HTTP listeners.
func (server *Server) Drain(ctx context.Context) error {
	server.mu.Lock()
	server.draining = true
	connections := make([]*websocket.Conn, 0, len(server.connections))
	for connection := range server.connections {
		connections = append(connections, connection)
	}
	server.mu.Unlock()
	for _, connection := range connections {
		go func(connection *websocket.Conn) {
			writeCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			_ = writeJSON(writeCtx, connection, map[string]any{
				"v": 1, "type": "server.draining", "payload": map[string]string{"reason": "server_draining"},
			})
			cancel()
			_ = connection.CloseNow()
		}(connection)
	}
	done := make(chan struct{})
	go func() {
		server.active.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (server *Server) authenticateCredential(request *http.Request) (peer, error) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 {
		return peer{}, store.ErrTicketInvalid
	}
	scheme, token, found := strings.Cut(values[0], " ")
	if !found || token == "" || strings.TrimSpace(token) != token {
		return peer{}, store.ErrTicketInvalid
	}
	switch scheme {
	case "DSH-Ticket":
		redemption, err := server.database.PrepareRealtimeTicket(request.Context(), token)
		if err != nil {
			return peer{}, err
		}
		if redemption.DeviceID == "" || redemption.RuntimeID == "" || redemption.ProofKeyThumbprint == "" || len(redemption.ProofPublicJWK) == 0 {
			return peer{}, store.ErrTicketInvalid
		}
		return peer{role: "device", deviceID: redemption.DeviceID, ticket: token, redemption: redemption}, nil
	case "DSH-Host":
		installation, err := server.database.LookupHostConnectionCredential(request.Context(), token)
		if err != nil {
			return peer{}, err
		}
		if installation.InstallationID == "" || installation.KeyThumbprint == "" || len(installation.PublicJWK) == 0 {
			return peer{}, store.ErrHostCredentialInvalid
		}
		return peer{role: "installation", installation: installation}, nil
	default:
		return peer{}, store.ErrTicketInvalid
	}
}

func (server *Server) writeAuthenticationError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrDatabaseUnavailable):
		writeError(response, http.StatusServiceUnavailable, "internal")
	default:
		writeError(response, http.StatusUnauthorized, "auth.proof_invalid")
	}
}

func (server *Server) runHandshake(parent context.Context, connection *websocket.Conn, peer peer) {
	connectionID, err := randomUUID()
	if err != nil {
		closePolicy(connection, "handshake unavailable")
		return
	}
	challengeID, err := randomUUID()
	if err != nil {
		closePolicy(connection, "handshake unavailable")
		return
	}
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		closePolicy(connection, "handshake unavailable")
		return
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	for index := range nonceBytes {
		nonceBytes[index] = 0
	}
	now := time.Now().UTC()
	challengeExpires := now.Add(handshakeTimeout)
	if peer.role == "device" && peer.redemption.ExpiresAt.Before(challengeExpires) {
		challengeExpires = peer.redemption.ExpiresAt
	}
	if peer.role == "installation" && peer.installation.ExpiresAt.Before(challengeExpires) {
		challengeExpires = peer.installation.ExpiresAt
	}
	if !challengeExpires.After(now) {
		closePolicy(connection, "credential expired")
		return
	}
	if writeJSON(parent, connection, map[string]any{
		"v": 1, "type": "challenge", "payload": map[string]any{
			"connection_id": connectionID, "challenge_id": challengeID,
			"nonce": nonce, "role": peer.role, "expires_at": challengeExpires,
		},
	}) != nil {
		return
	}
	proofCtx, cancel := context.WithDeadline(parent, challengeExpires)
	messageType, data, err := connection.Read(proofCtx)
	cancel()
	if err != nil || messageType != websocket.MessageText || int64(len(data)) > maxFrameBytes {
		closePolicy(connection, "handshake rejected")
		return
	}
	envelope, err := decodeEnvelope(data, "hello.proof")
	if err != nil {
		closePolicy(connection, "handshake rejected")
		return
	}
	if peer.role == "device" {
		server.finishDeviceHandshake(parent, connection, peer, connectionID, challengeID, nonce, envelope)
		return
	}
	server.finishHostHandshake(parent, connection, peer, connectionID, challengeID, nonce, envelope)
}

func (server *Server) finishDeviceHandshake(parent context.Context, connection *websocket.Conn, peer peer, connectionID, challengeID, nonce string, envelope wireEnvelope) {
	var payload deviceHandshakePayload
	if decodePayload(envelope.Payload, &payload) != nil {
		closePolicy(connection, "handshake rejected")
		return
	}
	hello, err := normalizeDeviceHello(payload, peer.deviceID)
	if err != nil {
		closePolicy(connection, "handshake rejected")
		return
	}
	helloDigest := hello.digest()
	expected := auth.RelayHandshakeExpectation{
		KeyThumbprint: peer.redemption.ProofKeyThumbprint,
		Issuer:        peer.deviceID,
		ChallengeID:   challengeID,
		ConnectionID:  connectionID,
		Nonce:         nonce,
		RuntimeID:     peer.redemption.RuntimeID,
		HelloSHA256:   helloDigest,
	}
	if auth.VerifyRelayHandshakeProof(payload.Proof, peer.redemption.ProofPublicJWK, expected) != nil {
		closePolicy(connection, "handshake rejected")
		return
	}
	redemption, err := server.database.ConsumeRealtimeTicket(parent, peer.ticket)
	if err != nil || redemption.DeviceID != peer.deviceID ||
		redemption.RuntimeID != peer.redemption.RuntimeID ||
		redemption.DeviceKeyVersion != peer.redemption.DeviceKeyVersion ||
		redemption.ProofKeyThumbprint != peer.redemption.ProofKeyThumbprint ||
		redemption.GrantVersion != peer.redemption.GrantVersion {
		closePolicy(connection, "ticket expired")
		return
	}
	thumbprint, err := auth.PublicP256JWKThumbprintJSON(redemption.ProofPublicJWK)
	if err != nil || thumbprint != peer.redemption.ProofKeyThumbprint {
		closePolicy(connection, "device key changed")
		return
	}
	leaseExpiresAt := time.Now().UTC().Add(deviceConnectionLife)
	leaseCtx, cancel := context.WithDeadline(parent, leaseExpiresAt)
	defer cancel()
	if writeJSON(leaseCtx, connection, map[string]any{
		"v": 1, "type": "hello.ok", "payload": map[string]any{
			"role": "device", "connection_id": connectionID,
			"device_id": redemption.DeviceID, "runtime_id": redemption.RuntimeID,
			"grant_version": redemption.GrantVersion, "scope": redemption.Scope,
			"protocols": []int{1}, "capabilities": intersectCapabilities(hello.Capabilities, []string{"connection.heartbeat.v1"}),
			"server_time": time.Now().UTC(), "heartbeat_seconds": heartbeatSeconds,
			"max_frame_bytes": maxFrameBytes, "lease_expires_at": leaseExpiresAt,
		},
	}) != nil {
		return
	}
	server.runHeartbeat(leaseCtx, connection, connectionID, nil)
}

func normalizeDeviceHello(payload deviceHandshakePayload, authenticatedDeviceID string) (normalizedDeviceHello, error) {
	if payload.DeviceID != authenticatedDeviceID || payload.Capabilities == nil || len(payload.Protocols) == 0 || len(payload.Protocols) > 8 || len(payload.Capabilities) > 64 {
		return normalizedDeviceHello{}, errors.New("relay: invalid device hello")
	}
	protocols := append([]int(nil), payload.Protocols...)
	sort.Ints(protocols)
	for index, protocol := range protocols {
		if protocol < 1 || protocol > 32 || index > 0 && protocols[index-1] == protocol {
			return normalizedDeviceHello{}, errors.New("relay: invalid device protocol list")
		}
	}
	if !containsInt(protocols, 1) {
		return normalizedDeviceHello{}, errors.New("relay: no common protocol")
	}
	capabilities := append([]string{}, payload.Capabilities...)
	for _, capability := range capabilities {
		if !capabilityPattern.MatchString(capability) {
			return normalizedDeviceHello{}, errors.New("relay: invalid capability")
		}
	}
	sort.Strings(capabilities)
	for index := 1; index < len(capabilities); index++ {
		if capabilities[index-1] == capabilities[index] {
			return normalizedDeviceHello{}, errors.New("relay: duplicate capability")
		}
	}
	return normalizedDeviceHello{DeviceID: authenticatedDeviceID, Protocols: protocols, Capabilities: capabilities}, nil
}

func (hello normalizedDeviceHello) digest() string {
	protocols := make([]string, len(hello.Protocols))
	for index, protocol := range hello.Protocols {
		protocols[index] = strconv.Itoa(protocol)
	}
	return auth.RelayHelloDigest("device", hello.DeviceID, strings.Join(protocols, ","), strings.Join(hello.Capabilities, "\n"))
}

func containsInt(values []int, want int) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func (server *Server) finishHostHandshake(parent context.Context, connection *websocket.Conn, peer peer, connectionID, challengeID, nonce string, envelope wireEnvelope) {
	var payload hostHandshakePayload
	if decodePayload(envelope.Payload, &payload) != nil {
		closePolicy(connection, "handshake rejected")
		return
	}
	hello, err := normalizeHostHello(payload)
	if err != nil {
		closePolicy(connection, "handshake rejected")
		return
	}
	helloDigest := hello.digest()
	expected := auth.RelayHandshakeExpectation{
		KeyThumbprint: peer.installation.KeyThumbprint,
		Issuer:        peer.installation.InstallationID,
		ChallengeID:   challengeID,
		ConnectionID:  connectionID,
		Nonce:         nonce,
		RuntimeID:     hello.RuntimeID,
		RuntimeEpoch:  hello.RuntimeEpoch,
		HelloSHA256:   helloDigest,
	}
	if auth.VerifyRelayHandshakeProof(payload.Proof, peer.installation.PublicJWK, expected) != nil {
		closePolicy(connection, "handshake rejected")
		return
	}
	if !peer.installation.ExpiresAt.After(time.Now()) {
		closePolicy(connection, "credential expired")
		return
	}
	registered, err := server.database.AttachRuntimeConnection(parent, store.RuntimeConnectionInput{
		InstallationID: peer.installation.InstallationID, KeyVersion: peer.installation.KeyVersion, RuntimeID: hello.RuntimeID,
		RuntimeEpoch: hello.RuntimeEpoch, ConnectionID: connectionID,
		DSHVersion: hello.DSHVersion, ApplicationVersion: hello.ApplicationVersion,
		PluginVersion: hello.PluginVersion, ProtocolVersion: hello.ProtocolVersion,
	})
	if err != nil {
		closePolicy(connection, "handshake rejected")
		return
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.database.DetachRuntimeConnection(ctx, registered.InstallationID, registered.RuntimeID, registered.RuntimeEpoch, registered.ConnectionID)
	}()
	leaseCtx, cancel := context.WithDeadline(parent, peer.installation.ExpiresAt)
	defer cancel()
	if err := leaseCtx.Err(); err != nil {
		closePolicy(connection, "credential expired")
		return
	}
	accepted := intersectCapabilities(hello.Capabilities, []string{"connection.heartbeat.v1"})
	if writeJSON(leaseCtx, connection, map[string]any{
		"v": 1, "type": "hello.ok", "payload": map[string]any{
			"role": "host", "connection_id": connectionID,
			"installation_id": registered.InstallationID, "runtime_id": registered.RuntimeID,
			"runtime_epoch": registered.RuntimeEpoch, "protocol_version": registered.ProtocolVersion,
			"protocols": []int{1}, "capabilities": accepted,
			"server_time": time.Now().UTC(), "heartbeat_seconds": heartbeatSeconds,
			"max_frame_bytes": maxFrameBytes, "lease_expires_at": peer.installation.ExpiresAt,
		},
	}) != nil {
		return
	}
	server.runHeartbeat(leaseCtx, connection, connectionID, &registered)
}

func (server *Server) runHeartbeat(parent context.Context, connection *websocket.Conn, connectionID string, host *store.RuntimeConnection) {
	var lastHeartbeat time.Time
	for {
		readCtx, cancel := context.WithTimeout(parent, connectionIdleTime)
		messageType, data, err := connection.Read(readCtx)
		cancel()
		if err != nil {
			return
		}
		if messageType != websocket.MessageText || int64(len(data)) > maxFrameBytes {
			closePolicy(connection, "invalid frame")
			return
		}
		envelope, err := decodeEnvelope(data, "ping")
		var payload struct{}
		if err != nil || decodePayload(envelope.Payload, &payload) != nil {
			writeErrorFrame(parent, connection, "protocol.invalid")
			closePolicy(connection, "invalid frame")
			return
		}
		now := time.Now()
		if !lastHeartbeat.IsZero() && now.Sub(lastHeartbeat) < time.Second {
			writeErrorFrame(parent, connection, "rate.limited")
			closePolicy(connection, "heartbeat rate exceeded")
			return
		}
		lastHeartbeat = now
		if host != nil {
			touchCtx, touchCancel := context.WithTimeout(parent, 3*time.Second)
			err = server.database.TouchRuntimeConnection(touchCtx,
				host.InstallationID, host.RuntimeID, host.RuntimeEpoch, host.ConnectionID)
			touchCancel()
			if err != nil {
				closePolicy(connection, "runtime connection expired")
				return
			}
		}
		if writeJSON(parent, connection, map[string]any{
			"v": 1, "type": "pong", "payload": map[string]any{
				"connection_id": connectionID, "server_time": now.UTC(),
			},
		}) != nil {
			return
		}
	}
}

func normalizeHostHello(payload hostHandshakePayload) (normalizedHostHello, error) {
	payload.RuntimeID = strings.TrimSpace(payload.RuntimeID)
	payload.RuntimeEpoch = strings.TrimSpace(payload.RuntimeEpoch)
	payload.DSHVersion = strings.TrimSpace(payload.DSHVersion)
	payload.ApplicationVersion = strings.TrimSpace(payload.ApplicationVersion)
	payload.PluginVersion = strings.TrimSpace(payload.PluginVersion)
	if !uuidPattern.MatchString(payload.RuntimeID) || !uuidPattern.MatchString(payload.RuntimeEpoch) ||
		payload.ProtocolVersion < 1 || payload.ProtocolVersion > 32 || payload.Capabilities == nil || len(payload.Capabilities) > 64 {
		return normalizedHostHello{}, errors.New("relay: invalid host hello")
	}
	for _, version := range []string{payload.DSHVersion, payload.ApplicationVersion, payload.PluginVersion} {
		if len(version) == 0 || len(version) > 128 || strings.IndexFunc(version, unicode.IsControl) >= 0 {
			return normalizedHostHello{}, errors.New("relay: invalid host version")
		}
	}
	capabilities := append([]string{}, payload.Capabilities...)
	for _, capability := range capabilities {
		if !capabilityPattern.MatchString(capability) {
			return normalizedHostHello{}, errors.New("relay: invalid capability")
		}
	}
	sort.Strings(capabilities)
	for index := 1; index < len(capabilities); index++ {
		if capabilities[index-1] == capabilities[index] {
			return normalizedHostHello{}, errors.New("relay: duplicate capability")
		}
	}
	return normalizedHostHello{
		RuntimeID: payload.RuntimeID, RuntimeEpoch: payload.RuntimeEpoch,
		DSHVersion: payload.DSHVersion, ApplicationVersion: payload.ApplicationVersion,
		PluginVersion: payload.PluginVersion, ProtocolVersion: payload.ProtocolVersion,
		Capabilities: capabilities,
	}, nil
}

func (hello normalizedHostHello) digest() string {
	return auth.RelayHelloDigest(
		"host", hello.RuntimeID, hello.RuntimeEpoch, hello.DSHVersion,
		hello.ApplicationVersion, hello.PluginVersion, strconv.Itoa(hello.ProtocolVersion),
		strings.Join(hello.Capabilities, "\n"),
	)
}

func intersectCapabilities(requested, supported []string) []string {
	allowed := make(map[string]struct{}, len(supported))
	for _, capability := range supported {
		allowed[capability] = struct{}{}
	}
	result := make([]string, 0, len(requested))
	for _, capability := range requested {
		if _, ok := allowed[capability]; ok {
			result = append(result, capability)
		}
	}
	return result
}

func decodeEnvelope(data []byte, expectedType string) (wireEnvelope, error) {
	var envelope wireEnvelope
	if auth.ValidateJSONObject(data) != nil {
		return wireEnvelope{}, errors.New("relay: invalid JSON envelope")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil || envelope.V != 1 || envelope.Type != expectedType || len(envelope.Payload) == 0 {
		return wireEnvelope{}, errors.New("relay: invalid protocol envelope")
	}
	return envelope, nil
}

func decodePayload(data []byte, target any) error {
	if auth.ValidateJSONObject(data) != nil {
		return errors.New("relay: invalid protocol payload")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("relay: invalid protocol payload")
	}
	return nil
}

func writeJSON(parent context.Context, connection *websocket.Conn, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data) > maxFrameBytes {
		return errors.New("relay: outgoing frame exceeds limit")
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	return connection.Write(ctx, websocket.MessageText, data)
}

func writeErrorFrame(parent context.Context, connection *websocket.Conn, code string) {
	_ = writeJSON(parent, connection, map[string]any{
		"v": 1, "type": "error", "payload": map[string]string{"code": code},
	})
}

func closePolicy(connection *websocket.Conn, reason string) {
	timer := time.AfterFunc(closeHandshakeGrace, func() { _ = connection.CloseNow() })
	defer timer.Stop()
	_ = connection.Close(websocket.StatusPolicyViolation, reason)
}

func writeError(response http.ResponseWriter, status int, code string) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(map[string]any{"ok": false, "error": map[string]string{"code": code}})
}

func randomUUID() (string, error) {
	data := make([]byte, 16)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	data[6] = (data[6] & 0x0f) | 0x40
	data[8] = (data[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		data[0:4], data[4:6], data[6:8], data[8:10], data[10:16]), nil
}
