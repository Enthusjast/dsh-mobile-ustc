package relay

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/store"
	"github.com/coder/websocket"
)

const (
	protocolName                = "dsh.remote.v1"
	maxFrameBytes               = 64 << 10
	maxMobileCommandFrame       = maxFrameBytes - 1024
	handshakeTimeout            = 15 * time.Second
	connectionIdleTime          = 45 * time.Second
	deviceConnectionLife        = 5 * time.Minute
	closeHandshakeGrace         = 250 * time.Millisecond
	heartbeatSeconds            = 20
	commandsPerSecond           = 20
	maxSessionCatalogBytes      = 8 << 20
	maxSessionCatalogBytesTotal = 64 << 20
)

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var capabilityPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
var supportedCapabilities = []string{"command.relay.v1", "connection.heartbeat.v1", "session.cancel.v1", "session.catalog.v1", "session.create.v1", "session.read.v1"}
var errRelayQueueFull = errors.New("relay: connection send queue is full")

type Repository interface {
	PrepareRealtimeTicket(context.Context, string) (store.TicketRedemption, error)
	ConsumeRealtimeTicket(context.Context, string) (store.TicketRedemption, error)
	ValidateRealtimeLease(context.Context, store.TicketRedemption) error
	LookupHostConnectionCredential(context.Context, string) (store.HostCredentialIdentity, error)
	AttachRuntimeConnection(context.Context, store.RuntimeConnectionInput) (store.RuntimeConnection, error)
	TouchRuntimeConnection(context.Context, string, string, string, string) error
	DetachRuntimeConnection(context.Context, string, string, string, string) error
	RecordRealtimeCommand(context.Context, store.TicketRedemption, string, string, string, string) (store.CommandStatus, error)
	RecordRealtimeSessionCreate(context.Context, store.TicketRedemption, string, string, string) (store.CommandStatus, error)
	RecordRealtimeCommandReceipt(context.Context, store.RelayCommandReceipt) (store.CommandStatus, error)
	MarkRealtimeCommandUnknown(context.Context, store.TicketRedemption, string, string, string) (store.CommandStatus, error)
	SyncRealtimeSessionCatalog(context.Context, store.RuntimeConnection, int64, bool, []store.SessionCatalogItem) error
	AuthorizeRealtimeSessionRead(context.Context, store.TicketRedemption, string) error
	InvalidRealtimeConnectionLeases(context.Context, []store.RealtimeConnectionLease) ([]string, error)
}

type Server struct {
	database      Repository
	mu            sync.Mutex
	connections   map[*websocket.Conn]*liveConnection
	hosts         map[string]*liveConnection
	devices       map[string]map[string]map[*liveConnection]struct{}
	active        sync.WaitGroup
	draining      bool
	catalogBytes  int
	subscriptions map[string]*sessionSubscription
}

type liveConnection struct {
	conn               *websocket.Conn
	peer               peer
	connectionID       string
	runtimeID          string
	runtimeEpoch       string
	capabilities       map[string]struct{}
	sendQueue          chan outboundFrame
	done               chan struct{}
	stopOnce           sync.Once
	lastHeartbeat      time.Time
	commandWindowStart time.Time
	commandWindowCount int
	catalogSnapshotID  string
	catalogMode        string
	catalogNextIndex   int
	catalogBytes       int
	catalogItems       []store.SessionCatalogItem
	subscriptions      map[string]*sessionSubscription
	closing            bool // Protected by Server.mu; prevents admission during unregister.
}

type outboundFrame struct {
	body   []byte
	result chan error
}

type peer struct {
	role         string
	deviceID     string
	ticket       string
	installation store.HostCredentialIdentity
	redemption   store.TicketRedemption
}

type wireEnvelope struct {
	V              int             `json:"v"`
	Type           string          `json:"type"`
	RequestID      string          `json:"request_id,omitempty"`
	RuntimeID      string          `json:"runtime_id,omitempty"`
	RuntimeEpoch   string          `json:"runtime_epoch,omitempty"`
	SessionID      string          `json:"session_id,omitempty"`
	DeviceID       string          `json:"device_id,omitempty"`
	UserID         string          `json:"user_id,omitempty"`
	PayloadSHA256  string          `json:"payload_sha256,omitempty"`
	SubscriptionID string          `json:"subscription_id,omitempty"`
	SyncID         string          `json:"sync_id,omitempty"`
	Payload        json.RawMessage `json:"payload"`
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

type messageContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type messageSubmitPayload struct {
	Mode    string           `json:"mode"`
	Content []messageContent `json:"content"`
}

type commandReceiptPayload struct {
	State          string                    `json:"state"`
	PayloadSHA256  string                    `json:"payload_sha256"`
	WorkspaceID    string                    `json:"workspace_id,omitempty"`
	CreatedSession *store.SessionCatalogItem `json:"created_session,omitempty"`
}

type sessionCatalogPayload struct {
	Mode     string                     `json:"mode"`
	Index    *int                       `json:"index"`
	Complete *bool                      `json:"complete"`
	Items    []store.SessionCatalogItem `json:"items"`
}

type normalizedMessageSubmit struct {
	Type      string               `json:"type"`
	SessionID string               `json:"session_id"`
	Payload   messageSubmitPayload `json:"payload"`
}

func New(database Repository) *Server {
	return &Server{
		database: database, connections: make(map[*websocket.Conn]*liveConnection),
		hosts: make(map[string]*liveConnection), devices: make(map[string]map[string]map[*liveConnection]struct{}),
		subscriptions: make(map[string]*sessionSubscription),
	}
}

func (live *liveConnection) writeLoop() {
	for {
		select {
		case <-live.done:
			return
		case frame := <-live.sendQueue:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err := live.conn.Write(ctx, websocket.MessageText, frame.body)
			cancel()
			frame.result <- err
			if err != nil {
				_ = live.conn.CloseNow()
				live.stop()
				return
			}
		}
	}
}

func (live *liveConnection) stop() {
	live.stopOnce.Do(func() { close(live.done) })
}

func (live *liveConnection) sendJSON(ctx context.Context, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data) > maxFrameBytes {
		return errors.New("relay: outgoing frame exceeds limit")
	}
	frame := outboundFrame{body: data, result: make(chan error, 1)}
	select {
	case <-live.done:
		return net.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	case live.sendQueue <- frame:
	default:
		return errRelayQueueFull
	}
	select {
	case err := <-frame.result:
		return err
	case <-live.done:
		return net.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (live *liveConnection) supports(capability string) bool {
	_, ok := live.capabilities[capability]
	return ok
}

func capabilitySet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func (server *Server) bindDevice(live *liveConnection, redemption store.TicketRedemption, connectionID string, capabilities []string) bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.draining || live.closing || server.connections[live.conn] != live {
		return false
	}
	live.peer.redemption = redemption
	live.peer.deviceID = redemption.DeviceID
	live.runtimeID = redemption.RuntimeID
	live.connectionID = connectionID
	live.capabilities = capabilitySet(capabilities)
	byDevice := server.devices[live.runtimeID]
	if byDevice == nil {
		byDevice = make(map[string]map[*liveConnection]struct{})
		server.devices[live.runtimeID] = byDevice
	}
	connections := byDevice[live.peer.deviceID]
	if connections == nil {
		connections = make(map[*liveConnection]struct{})
		byDevice[live.peer.deviceID] = connections
	}
	connections[live] = struct{}{}
	return true
}

func (server *Server) bindHost(live *liveConnection, connection store.RuntimeConnection, capabilities []string) bool {
	server.mu.Lock()
	if server.draining || live.closing || server.connections[live.conn] != live {
		server.mu.Unlock()
		return false
	}
	previous := server.hosts[connection.RuntimeID]
	server.hosts[connection.RuntimeID] = live
	live.runtimeID = connection.RuntimeID
	live.runtimeEpoch = connection.RuntimeEpoch
	live.connectionID = connection.ConnectionID
	live.capabilities = capabilitySet(capabilities)
	server.mu.Unlock()
	if previous != nil && previous != live {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = previous.sendJSON(ctx, map[string]any{
			"v": 1, "type": "runtime.changed", "payload": map[string]string{"runtime_id": connection.RuntimeID},
		})
		cancel()
		_ = previous.conn.CloseNow()
	}
	return true
}

func (server *Server) hostForRuntime(runtimeID string) *liveConnection {
	server.mu.Lock()
	defer server.mu.Unlock()
	host := server.hosts[runtimeID]
	if host != nil && host.closing {
		return nil
	}
	return host
}

func (server *Server) devicesForRuntime(runtimeID, deviceID string) []*liveConnection {
	server.mu.Lock()
	defer server.mu.Unlock()
	byDevice := server.devices[runtimeID]
	connections := byDevice[deviceID]
	result := make([]*liveConnection, 0, len(connections))
	for connection := range connections {
		if !connection.closing {
			result = append(result, connection)
		}
	}
	return result
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
	live, registered := server.registerConnection(connection, peer)
	if !registered {
		closePolicy(connection, "server draining")
		_ = connection.CloseNow()
		return
	}
	defer server.unregisterConnection(live)
	defer connection.Close(websocket.StatusNormalClosure, "connection closed")
	if connection.Subprotocol() != protocolName {
		closePolicy(connection, "protocol required")
		return
	}
	server.runHandshake(request.Context(), live)
}

func (server *Server) registerConnection(connection *websocket.Conn, identity peer) (*liveConnection, bool) {
	server.mu.Lock()
	if server.draining {
		server.mu.Unlock()
		return nil, false
	}
	live := &liveConnection{conn: connection, peer: identity, sendQueue: make(chan outboundFrame, 16), done: make(chan struct{})}
	server.active.Add(1)
	server.connections[connection] = live
	server.mu.Unlock()
	go live.writeLoop()
	return live, true
}

func (server *Server) unregisterConnection(live *liveConnection) {
	server.closeConnectionSubscriptions(live)
	server.mu.Lock()
	delete(server.connections, live.conn)
	server.catalogBytes -= live.catalogBytes
	if server.catalogBytes < 0 {
		server.catalogBytes = 0
	}
	live.catalogSnapshotID = ""
	live.catalogMode = ""
	live.catalogNextIndex = 0
	live.catalogBytes = 0
	live.catalogItems = nil
	if live.peer.role == "installation" && server.hosts[live.runtimeID] == live {
		delete(server.hosts, live.runtimeID)
	}
	if live.peer.role == "device" {
		byDevice := server.devices[live.runtimeID]
		if byDevice != nil {
			delete(byDevice[live.peer.deviceID], live)
			if len(byDevice[live.peer.deviceID]) == 0 {
				delete(byDevice, live.peer.deviceID)
			}
			if len(byDevice) == 0 {
				delete(server.devices, live.runtimeID)
			}
		}
	}
	server.mu.Unlock()
	live.stop()
	server.active.Done()
}

// Drain rejects future sockets, closes current sockets, and waits for their
// runtime cleanup to finish before the caller shuts down HTTP listeners.
func (server *Server) Drain(ctx context.Context) error {
	server.mu.Lock()
	server.draining = true
	connections := make([]*liveConnection, 0, len(server.connections))
	for _, connection := range server.connections {
		connections = append(connections, connection)
	}
	server.mu.Unlock()
	for _, connection := range connections {
		go func(connection *liveConnection) {
			writeCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			_ = connection.sendJSON(writeCtx, map[string]any{
				"v": 1, "type": "server.draining", "payload": map[string]string{"reason": "server_draining"},
			})
			cancel()
			_ = connection.conn.CloseNow()
			connection.stop()
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

func (server *Server) runHandshake(parent context.Context, live *liveConnection) {
	connection := live.conn
	peer := live.peer
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
		server.finishDeviceHandshake(parent, live, connectionID, challengeID, nonce, envelope)
		return
	}
	server.finishHostHandshake(parent, live, connectionID, challengeID, nonce, envelope)
}

func (server *Server) finishDeviceHandshake(parent context.Context, live *liveConnection, connectionID, challengeID, nonce string, envelope wireEnvelope) {
	connection := live.conn
	peer := live.peer
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
	accepted := intersectCapabilities(hello.Capabilities, supportedCapabilities)
	if writeJSON(leaseCtx, connection, map[string]any{
		"v": 1, "type": "hello.ok", "payload": map[string]any{
			"role": "device", "connection_id": connectionID,
			"device_id": redemption.DeviceID, "runtime_id": redemption.RuntimeID,
			"grant_version": redemption.GrantVersion, "scope": redemption.Scope,
			"protocols": []int{1}, "capabilities": accepted,
			"server_time": time.Now().UTC(), "heartbeat_seconds": heartbeatSeconds,
			"max_frame_bytes": maxFrameBytes, "lease_expires_at": leaseExpiresAt,
		},
	}) != nil {
		return
	}
	if !server.bindDevice(live, redemption, connectionID, accepted) {
		closePolicy(connection, "server draining")
		return
	}
	server.runHeartbeat(leaseCtx, live, nil)
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

func (server *Server) finishHostHandshake(parent context.Context, live *liveConnection, connectionID, challengeID, nonce string, envelope wireEnvelope) {
	connection := live.conn
	peer := live.peer
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
	accepted := intersectCapabilities(hello.Capabilities, supportedCapabilities)
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
	if !server.bindHost(live, registered, accepted) {
		closePolicy(connection, "server draining")
		return
	}
	server.runHeartbeat(leaseCtx, live, &registered)
}

func (server *Server) runHeartbeat(parent context.Context, live *liveConnection, host *store.RuntimeConnection) {
	connection := live.conn
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
		envelope, err := decodeWireFrame(data)
		if err != nil {
			server.sendProtocolError(parent, live, "protocol.invalid", nil)
			closePolicy(connection, "invalid frame")
			return
		}
		switch envelope.Type {
		case "ping":
			if !frameHasNoRoutingFields(envelope) {
				server.sendProtocolError(parent, live, "protocol.invalid", nil)
				closePolicy(connection, "invalid heartbeat")
				return
			}
			var empty struct{}
			if decodePayload(envelope.Payload, &empty) != nil {
				server.sendProtocolError(parent, live, "protocol.invalid", nil)
				closePolicy(connection, "invalid heartbeat")
				return
			}
			now := time.Now()
			if !live.lastHeartbeat.IsZero() && now.Sub(live.lastHeartbeat) < time.Second {
				server.sendProtocolError(parent, live, "rate.limited", nil)
				closePolicy(connection, "heartbeat rate exceeded")
				return
			}
			live.lastHeartbeat = now
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
			if live.sendJSON(parent, map[string]any{
				"v": 1, "type": "pong", "payload": map[string]any{
					"connection_id": live.connectionID, "server_time": now.UTC(),
				},
			}) != nil {
				return
			}
		case "message.submit", "session.cancel", "session.create":
			if live.peer.role != "device" {
				server.sendProtocolError(parent, live, "access.denied", &envelope)
				closePolicy(connection, "operation denied")
				return
			}
			if len(data) > maxMobileCommandFrame {
				server.sendProtocolError(parent, live, "protocol.frame_too_large", &envelope)
				continue
			}
			now := time.Now()
			if live.commandWindowStart.IsZero() || now.Sub(live.commandWindowStart) >= time.Second {
				live.commandWindowStart = now
				live.commandWindowCount = 0
			}
			live.commandWindowCount++
			if live.commandWindowCount > commandsPerSecond {
				server.sendProtocolError(parent, live, "rate.limited", &envelope)
				continue
			}
			if envelope.Type == "session.create" {
				server.routeSessionCreate(parent, live, envelope)
			} else {
				server.routeSessionCommand(parent, live, envelope)
			}
		case "command.receipt":
			if live.peer.role != "installation" || host == nil || !live.peer.installation.ExpiresAt.After(time.Now()) {
				server.sendProtocolError(parent, live, "access.denied", &envelope)
				closePolicy(connection, "operation denied")
				return
			}
			server.routeCommandReceipt(parent, live, host, envelope)
		case "session.subscribe", "session.unsubscribe", "session.page":
			if live.peer.role != "device" {
				server.sendProtocolError(parent, live, "access.denied", &envelope)
				closePolicy(connection, "operation denied")
				return
			}
			now := time.Now()
			if live.commandWindowStart.IsZero() || now.Sub(live.commandWindowStart) >= time.Second {
				live.commandWindowStart, live.commandWindowCount = now, 0
			}
			live.commandWindowCount++
			if live.commandWindowCount > commandsPerSecond {
				server.sendProtocolError(parent, live, "rate.limited", &envelope)
				continue
			}
			server.routeSessionRead(parent, live, envelope)
		case "session.snapshot", "session.event", "session.checkpoint", "assistant.start", "assistant.chunk", "assistant.end", "session.page.result", "session.fragment", "session.error", "session.closed":
			if live.peer.role != "installation" || host == nil || !live.peer.installation.ExpiresAt.After(time.Now()) {
				server.sendProtocolError(parent, live, "access.denied", &envelope)
				closePolicy(connection, "operation denied")
				return
			}
			server.routeSessionContent(parent, live, envelope)
		case "session.catalog":
			if live.peer.role != "installation" || host == nil || !live.peer.installation.ExpiresAt.After(time.Now()) {
				server.sendProtocolError(parent, live, "access.denied", &envelope)
				closePolicy(connection, "operation denied")
				return
			}
			server.routeSessionCatalog(parent, live, host, envelope, data)
		default:
			server.sendProtocolError(parent, live, "protocol.unsupported", &envelope)
			closePolicy(connection, "unsupported frame")
			return
		}
	}
}

func (server *Server) routeSessionCatalog(parent context.Context, live *liveConnection, host *store.RuntimeConnection, envelope wireEnvelope, data []byte) {
	if !live.supports("session.catalog.v1") {
		server.sendProtocolError(parent, live, "protocol.unsupported", &envelope)
		return
	}
	if !uuidPattern.MatchString(envelope.RequestID) || envelope.RuntimeID != live.runtimeID ||
		envelope.RuntimeEpoch != live.runtimeEpoch || envelope.SessionID != "" || envelope.DeviceID != "" ||
		envelope.UserID != "" || envelope.PayloadSHA256 != "" || envelope.SubscriptionID != "" || envelope.SyncID != "" || len(data) > maxFrameBytes {
		server.sendProtocolError(parent, live, "protocol.invalid", &envelope)
		return
	}
	var payload sessionCatalogPayload
	if decodePayload(envelope.Payload, &payload) != nil || payload.Index == nil || payload.Complete == nil ||
		payload.Items == nil || *payload.Index < 0 || len(payload.Items) > 256 ||
		(payload.Mode != "snapshot" && payload.Mode != "delta") ||
		(!*payload.Complete && len(payload.Items) == 0) ||
		(payload.Mode == "delta" && len(payload.Items) == 0) {
		server.sendProtocolError(parent, live, "protocol.invalid", &envelope)
		return
	}
	index, complete := *payload.Index, *payload.Complete
	var (
		items         []store.SessionCatalogItem
		invalid       bool
		rateLimited   bool
		replace       bool
		applyingBytes int
	)
	server.mu.Lock()
	if index == 0 {
		server.catalogBytes -= live.catalogBytes
		live.catalogSnapshotID = envelope.RequestID
		live.catalogMode = payload.Mode
		live.catalogNextIndex = 0
		live.catalogBytes = 0
		live.catalogItems = nil
	}
	if live.catalogSnapshotID != envelope.RequestID || live.catalogMode != payload.Mode || live.catalogNextIndex != index {
		invalid = true
	} else if live.catalogBytes+len(data) > maxSessionCatalogBytes ||
		server.catalogBytes+len(data) > maxSessionCatalogBytesTotal || len(live.catalogItems)+len(payload.Items) > 20_000 {
		rateLimited = true
	} else {
		live.catalogNextIndex++
		live.catalogBytes += len(data)
		server.catalogBytes += len(data)
		live.catalogItems = append(live.catalogItems, payload.Items...)
		if complete {
			items = live.catalogItems
			replace = live.catalogMode == "snapshot"
			applyingBytes = live.catalogBytes
			live.catalogSnapshotID = ""
			live.catalogMode = ""
			live.catalogNextIndex = 0
			live.catalogBytes = 0
			live.catalogItems = nil
		}
	}
	if invalid || rateLimited {
		server.catalogBytes -= live.catalogBytes
		live.catalogSnapshotID = ""
		live.catalogMode = ""
		live.catalogNextIndex = 0
		live.catalogBytes = 0
		live.catalogItems = nil
	}
	server.mu.Unlock()
	if invalid {
		server.sendProtocolError(parent, live, "protocol.invalid", &envelope)
		return
	}
	if rateLimited {
		server.sendProtocolError(parent, live, "rate.limited", &envelope)
		return
	}
	if !complete {
		return
	}
	// Keep completed snapshots in the global budget while database work is
	// queued; otherwise every waiting host could retain another full catalog.
	defer func() {
		server.mu.Lock()
		server.catalogBytes -= applyingBytes
		server.mu.Unlock()
	}()
	if err := server.database.SyncRealtimeSessionCatalog(parent, *host, live.peer.installation.KeyVersion, replace, items); err != nil {
		if errors.Is(err, store.ErrRuntimeConnectionStale) {
			closePolicy(live.conn, "runtime connection expired")
			return
		}
		code := "internal"
		if errors.Is(err, store.ErrSessionCatalogInvalid) {
			code = "protocol.invalid"
		}
		server.sendProtocolError(parent, live, code, &envelope)
		return
	}
	_ = live.sendJSON(parent, map[string]any{
		"v": 1, "type": "session.catalog.ack", "request_id": envelope.RequestID,
		"runtime_id": live.runtimeID, "runtime_epoch": live.runtimeEpoch,
		"payload": map[string]any{"session_count": len(items), "server_time": time.Now().UTC()},
	})
}

func (server *Server) routeSessionCommand(parent context.Context, live *liveConnection, envelope wireEnvelope) {
	capability := "command.relay.v1"
	if envelope.Type == "session.cancel" {
		capability = "session.cancel.v1"
	}
	if !live.supports("command.relay.v1") || !live.supports(capability) {
		server.sendProtocolError(parent, live, "protocol.unsupported", &envelope)
		return
	}
	if !uuidPattern.MatchString(envelope.RequestID) || envelope.RuntimeID != live.runtimeID ||
		!uuidPattern.MatchString(envelope.SessionID) ||
		(envelope.Type == "message.submit" && envelope.RuntimeEpoch != "") ||
		(envelope.Type == "session.cancel" && !uuidPattern.MatchString(envelope.RuntimeEpoch)) ||
		envelope.DeviceID != "" || envelope.UserID != "" || envelope.PayloadSHA256 != "" || envelope.SubscriptionID != "" || envelope.SyncID != "" {
		server.sendProtocolError(parent, live, "protocol.invalid", &envelope)
		return
	}
	var payload any
	var digest string
	if envelope.Type == "message.submit" {
		var submit messageSubmitPayload
		if decodePayload(envelope.Payload, &submit) != nil || normalizeMessageSubmit(submit) != nil {
			server.sendProtocolError(parent, live, "protocol.invalid", &envelope)
			return
		}
		payload = submit
		digest, _ = messageSubmitDigest(envelope.SessionID, submit)
	} else {
		if decodePayload(envelope.Payload, &struct{}{}) != nil {
			server.sendProtocolError(parent, live, "protocol.invalid", &envelope)
			return
		}
		payload = struct{}{}
		digest = sessionCancelDigest(envelope.SessionID, envelope.RuntimeEpoch)
	}
	host := server.hostForRuntime(live.runtimeID)
	if host == nil || !host.peer.installation.ExpiresAt.After(time.Now()) {
		server.sendProtocolError(parent, live, "runtime.offline", &envelope)
		return
	}
	if !host.supports("command.relay.v1") || !host.supports(capability) {
		server.sendProtocolError(parent, live, "protocol.unsupported", &envelope)
		return
	}
	if envelope.Type == "session.cancel" && envelope.RuntimeEpoch != host.runtimeEpoch {
		server.sendProtocolError(parent, live, "runtime.changed", &envelope)
		return
	}
	touchCtx, touchCancel := context.WithTimeout(parent, 3*time.Second)
	err := server.database.TouchRuntimeConnection(touchCtx,
		host.peer.installation.InstallationID, host.runtimeID, host.runtimeEpoch, host.connectionID)
	touchCancel()
	if err != nil {
		_ = host.conn.CloseNow()
		server.sendProtocolError(parent, live, "runtime.offline", &envelope)
		return
	}
	status, err := server.database.RecordRealtimeCommand(parent, live.peer.redemption, envelope.Type, envelope.RequestID, envelope.SessionID, digest)
	if err != nil {
		server.sendProtocolError(parent, live, commandErrorCode(err), &envelope)
		return
	}
	server.forwardRecordedCommand(parent, live, host, envelope, payload, digest, status)
}

func (server *Server) forwardRecordedCommand(parent context.Context, live, host *liveConnection, envelope wireEnvelope, payload any, digest string, status store.CommandStatus) {
	if err := server.database.ValidateRealtimeLease(parent, live.peer.redemption); err != nil {
		server.revokeDeviceConnection(parent, live, err)
		return
	}
	if status.State == "received" {
		forward := map[string]any{
			"v": 1, "type": envelope.Type, "request_id": envelope.RequestID,
			"runtime_id": live.runtimeID, "runtime_epoch": host.runtimeEpoch, "session_id": envelope.SessionID,
			"user_id": live.peer.redemption.UserID, "device_id": live.peer.deviceID,
			"payload_sha256": digest, "payload": payload,
		}
		if envelope.SessionID == "" {
			delete(forward, "session_id")
		}
		sendCtx, cancel := context.WithTimeout(parent, 2*time.Second)
		err := host.sendJSON(sendCtx, forward)
		cancel()
		if err != nil {
			if errors.Is(err, errRelayQueueFull) {
				server.sendProtocolError(parent, live, "rate.limited", &envelope)
				return
			}
			unknown, markErr := server.database.MarkRealtimeCommandUnknown(parent, live.peer.redemption, envelope.RequestID, envelope.SessionID, digest)
			if markErr == nil {
				_ = server.sendCommandReceipt(parent, live, unknown, host.runtimeEpoch)
			} else {
				server.sendProtocolError(parent, live, "command.outcome_unknown", &envelope)
			}
			return
		}
	}
	_ = server.sendCommandReceipt(parent, live, status, host.runtimeEpoch)
}

func (server *Server) routeCommandReceipt(parent context.Context, live *liveConnection, host *store.RuntimeConnection, envelope wireEnvelope) {
	if !live.supports("command.relay.v1") {
		server.sendProtocolError(parent, live, "protocol.unsupported", &envelope)
		return
	}
	if !uuidPattern.MatchString(envelope.RequestID) || envelope.RuntimeID != live.runtimeID ||
		envelope.RuntimeEpoch != live.runtimeEpoch || (envelope.SessionID != "" && !uuidPattern.MatchString(envelope.SessionID)) ||
		!uuidPattern.MatchString(envelope.DeviceID) || envelope.UserID != "" || envelope.PayloadSHA256 != "" || envelope.SubscriptionID != "" || envelope.SyncID != "" {
		server.sendProtocolError(parent, live, "protocol.invalid", &envelope)
		return
	}
	var payload commandReceiptPayload
	if decodePayload(envelope.Payload, &payload) != nil || !validSHA256Hex(payload.PayloadSHA256) {
		server.sendProtocolError(parent, live, "protocol.invalid", &envelope)
		return
	}
	if (payload.WorkspaceID == "" && envelope.SessionID == "") ||
		(payload.WorkspaceID != "" && (!uuidPattern.MatchString(payload.WorkspaceID) || !live.supports("session.create.v1"))) {
		server.sendProtocolError(parent, live, "protocol.invalid", &envelope)
		return
	}
	status, err := server.database.RecordRealtimeCommandReceipt(parent, store.RelayCommandReceipt{
		InstallationID: host.InstallationID, KeyVersion: live.peer.installation.KeyVersion,
		RuntimeID: live.runtimeID, RuntimeEpoch: live.runtimeEpoch, ConnectionID: live.connectionID,
		DeviceID: envelope.DeviceID, RequestID: envelope.RequestID, SessionID: envelope.SessionID,
		WorkspaceID: payload.WorkspaceID, CreatedSession: payload.CreatedSession,
		PayloadSHA256: payload.PayloadSHA256, State: payload.State,
	})
	if err != nil {
		server.sendProtocolError(parent, live, commandErrorCode(err), &envelope)
		return
	}
	for _, device := range server.devicesForRuntime(live.runtimeID, envelope.DeviceID) {
		if err := server.sendCommandReceipt(parent, device, status, live.runtimeEpoch); err != nil {
			_ = device.conn.CloseNow()
		}
	}
}

func (server *Server) sendCommandReceipt(ctx context.Context, live *liveConnection, status store.CommandStatus, runtimeEpoch string) error {
	if live.peer.role == "device" {
		if status.WorkspaceID != "" && (!live.supports("session.create.v1") || !slices.Contains(live.peer.redemption.Scope.Workspaces, status.WorkspaceID) ||
			(!slices.Contains(live.peer.redemption.Scope.Actions, "session.create") && !slices.Contains(live.peer.redemption.Scope.Actions, "command.status"))) {
			return nil
		}
		if err := server.database.ValidateRealtimeLease(ctx, live.peer.redemption); err != nil {
			server.revokeDeviceConnection(ctx, live, err)
			return err
		}
	}
	frame := map[string]any{
		"v": 1, "type": "command.receipt", "request_id": status.RequestID,
		"runtime_id":    live.runtimeID,
		"runtime_epoch": runtimeEpoch,
		"payload": map[string]any{
			"state": status.State, "payload_sha256": status.PayloadSHA256, "updated_at": status.UpdatedAt,
		},
	}
	if status.SessionID != "" {
		frame["session_id"] = status.SessionID
	}
	if status.WorkspaceID != "" {
		frame["payload"].(map[string]any)["workspace_id"] = status.WorkspaceID
	}
	return live.sendJSON(ctx, frame)
}

func (server *Server) revokeDeviceConnection(ctx context.Context, live *liveConnection, cause error) {
	code := "access.revoked"
	if errors.Is(cause, store.ErrDatabaseUnavailable) {
		code = "internal"
	}
	_ = live.sendJSON(ctx, map[string]any{"v": 1, "type": "access.revoked", "payload": map[string]string{"code": code}})
	_ = live.conn.CloseNow()
}

func (server *Server) sendProtocolError(ctx context.Context, live *liveConnection, code string, request *wireEnvelope) {
	frame := map[string]any{"v": 1, "type": "error", "payload": map[string]string{"code": code}}
	if request != nil {
		frame["request_id"] = request.RequestID
		if request.RuntimeID != "" {
			frame["runtime_id"] = request.RuntimeID
		}
		if request.SessionID != "" {
			frame["session_id"] = request.SessionID
		}
	}
	_ = live.sendJSON(ctx, frame)
}

func commandErrorCode(err error) string {
	switch {
	case errors.Is(err, store.ErrCommandConflict):
		return "command.request_conflict"
	case errors.Is(err, store.ErrRuntimeConnectionStale):
		return "runtime.changed"
	case errors.Is(err, store.ErrAccessDenied), errors.Is(err, store.ErrTicketInvalid):
		return "access.denied"
	case errors.Is(err, store.ErrDatabaseUnavailable):
		return "internal"
	case errors.Is(err, store.ErrGrantInvalid):
		return "grant.invalid"
	case errors.Is(err, store.ErrCommandTransition):
		return "protocol.invalid"
	default:
		return "internal"
	}
}

func normalizeMessageSubmit(payload messageSubmitPayload) error {
	if payload.Mode != "queue" && payload.Mode != "steer" || len(payload.Content) == 0 || len(payload.Content) > 16 {
		return errors.New("relay: invalid message submit payload")
	}
	for _, item := range payload.Content {
		if item.Type != "text" || len(item.Text) == 0 || utf8.RuneCountInString(item.Text) > 32_768 || strings.TrimSpace(item.Text) == "" {
			return errors.New("relay: invalid text content")
		}
		for _, char := range item.Text {
			if unicode.IsControl(char) && char != '\n' && char != '\t' && char != '\r' {
				return errors.New("relay: control character in text")
			}
		}
	}
	return nil
}

func messageSubmitDigest(sessionID string, payload messageSubmitPayload) (string, error) {
	// JCS order for this text-only command is fixed: top-level payload/session/type,
	// payload content/mode, and each text block text/type.
	encoded := []byte(`{"payload":{"content":[`)
	for index, item := range payload.Content {
		if index > 0 {
			encoded = append(encoded, ',')
		}
		encoded = append(encoded, `{"text":`...)
		encoded = appendJSONString(encoded, item.Text)
		encoded = append(encoded, `,"type":"text"}`...)
	}
	encoded = append(encoded, `],"mode":`...)
	encoded = appendJSONString(encoded, payload.Mode)
	encoded = append(encoded, `},"session_id":`...)
	encoded = appendJSONString(encoded, sessionID)
	encoded = append(encoded, `,"type":"message.submit"}`...)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func sessionCancelDigest(sessionID, runtimeEpoch string) string {
	// Identifiers are validated UUIDs. Bind cancel retries to their original
	// runtime so a delayed command cannot stop work after a process restart.
	encoded := `{"payload":{},"runtime_epoch":"` + runtimeEpoch + `","session_id":"` + sessionID + `","type":"session.cancel"}`
	digest := sha256.Sum256([]byte(encoded))
	return hex.EncodeToString(digest[:])
}

func appendJSONString(output []byte, value string) []byte {
	output = append(output, '"')
	for _, char := range value {
		switch char {
		case '"':
			output = append(output, '\\', '"')
		case '\\':
			output = append(output, '\\', '\\')
		case '\b':
			output = append(output, '\\', 'b')
		case '\f':
			output = append(output, '\\', 'f')
		case '\n':
			output = append(output, '\\', 'n')
		case '\r':
			output = append(output, '\\', 'r')
		case '\t':
			output = append(output, '\\', 't')
		default:
			if char < 0x20 {
				output = append(output, '\\', 'u', '0', '0', lowerHex(byte(char>>4)), lowerHex(byte(char&0xf)))
			} else {
				output = utf8.AppendRune(output, char)
			}
		}
	}
	return append(output, '"')
}

func lowerHex(value byte) byte {
	if value < 10 {
		return '0' + value
	}
	return 'a' + value - 10
}

func validSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
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

func decodeWireFrame(data []byte) (wireEnvelope, error) {
	var envelope wireEnvelope
	if auth.ValidateJSONObject(data) != nil {
		return wireEnvelope{}, errors.New("relay: invalid JSON envelope")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil || envelope.V != 1 || envelope.Type == "" || len(envelope.Payload) == 0 {
		return wireEnvelope{}, errors.New("relay: invalid protocol envelope")
	}
	return envelope, nil
}

func decodeEnvelope(data []byte, expectedType string) (wireEnvelope, error) {
	envelope, err := decodeWireFrame(data)
	if err != nil || envelope.Type != expectedType || !frameHasNoRoutingFields(envelope) {
		return wireEnvelope{}, errors.New("relay: invalid protocol envelope")
	}
	return envelope, nil
}

func frameHasNoRoutingFields(envelope wireEnvelope) bool {
	return envelope.RequestID == "" && envelope.RuntimeID == "" && envelope.RuntimeEpoch == "" &&
		envelope.SessionID == "" && envelope.DeviceID == "" && envelope.UserID == "" && envelope.PayloadSHA256 == "" && envelope.SubscriptionID == "" && envelope.SyncID == ""
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
