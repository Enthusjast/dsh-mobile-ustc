package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"dsh-mobile-ustc/services/remote/internal/store"
	"github.com/coder/websocket"
)

const privateRelayPath = "/internal/relay/v1/device"
const relayNodeHeader = "X-DSH-Relay-Node"
const relayGenerationHeader = "X-DSH-Relay-Generation"
const relayRouteHeader = "X-DSH-Relay-Route"

type RoutingDirectory interface {
	RelayIdentity() store.RelayNode
	LookupRuntimeRoute(context.Context, string) (store.RuntimeRoute, error)
	ValidateRelayNode(context.Context, string, string) error
}

type RoutingConfig struct {
	Directory           RoutingDirectory
	ClientTLS           *tls.Config
	MaxProxyConnections int
}

type nodeRouting struct {
	RoutingConfig
	identity store.RelayNode
}

type relayTunnel struct {
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex
	front      *websocket.Conn
	back       *websocket.Conn
	frontClose func() error
	backClose  func() error
	inflight   [2]atomic.Int64
}

// A dedicated cluster CA must issue exactly one node URI SAN in each leaf.
// Normal chain, hostname, lifetime and EKU checks remain TLS responsibilities.
func RelayCertificateNode(certificate *x509.Certificate) (string, error) {
	if certificate == nil || len(certificate.URIs) != 1 {
		return "", errors.New("relay: node URI is required")
	}
	uri := certificate.URIs[0]
	prefix := "spiffe://dsh-remote/relay/"
	value := uri.String()
	if len(value) != len(prefix)+36 || value[:len(prefix)] != prefix || !uuidPattern.MatchString(value[len(prefix):]) {
		return "", errors.New("relay: node URI is invalid")
	}
	return value[len(prefix):], nil
}

func (server *Server) ConfigureRouting(config RoutingConfig) error {
	if config.Directory == nil {
		return errors.New("relay: directory is required")
	}
	identity := config.Directory.RelayIdentity()
	if !uuidPattern.MatchString(identity.NodeID) || !uuidPattern.MatchString(identity.Generation) ||
		(identity.Origin != "" && !store.ValidRelayOrigin(identity.Origin)) {
		return errors.New("relay: node identity is invalid")
	}
	if config.MaxProxyConnections == 0 {
		config.MaxProxyConnections = 4096
	}
	if config.MaxProxyConnections < 1 || config.MaxProxyConnections > 12000 {
		return errors.New("relay: proxy connection budget is invalid")
	}
	if config.ClientTLS != nil {
		if identity.Origin == "" || config.ClientTLS.InsecureSkipVerify || config.ClientTLS.MinVersion < tls.VersionTLS13 ||
			config.ClientTLS.RootCAs == nil || len(config.ClientTLS.Certificates) != 1 || len(config.ClientTLS.Certificates[0].Certificate) == 0 || config.ClientTLS.ServerName != "" {
			return errors.New("relay: verified mutual TLS is required")
		}
		certificate, err := x509.ParseCertificate(config.ClientTLS.Certificates[0].Certificate[0])
		if err != nil {
			return errors.New("relay: node certificate is invalid")
		}
		node, err := RelayCertificateNode(certificate)
		if err != nil || node != identity.NodeID {
			return errors.New("relay: certificate does not identify this node")
		}
		config.ClientTLS = config.ClientTLS.Clone()
	} else if identity.Origin != "" {
		return errors.New("relay: private origin requires mutual TLS")
	}
	// Startup only, before admission or metric collection can observe routing.
	server.routing = &nodeRouting{config, identity}
	server.tunnels = make(map[*relayTunnel]struct{})
	return nil
}

func (server *Server) resolveDevice(response http.ResponseWriter, request *http.Request, identity peer) (*store.RuntimeRoute, bool) {
	if server.routing == nil || identity.role != "device" {
		return nil, false
	}
	route, err := server.routing.Directory.LookupRuntimeRoute(request.Context(), identity.redemption.RuntimeID)
	if errors.Is(err, store.ErrRuntimeConnectionStale) {
		return nil, false // An offline phone may still connect to reconcile metadata.
	}
	if err != nil {
		writeError(response, http.StatusServiceUnavailable, "internal")
		return nil, true
	}
	if route.NodeID == server.routing.identity.NodeID && route.Generation == server.routing.identity.Generation {
		return &route, false
	}
	server.proxyDevice(response, request, identity, route)
	return nil, true
}

func (server *Server) PrivateRelayHandler(owner ...http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == privateOwnerHTTPPath && len(owner) == 1 {
			server.servePrivateOwnerHTTP(w, r, owner[0])
			return
		}
		server.servePrivateRelay(w, r)
	})
}

func singleHeader(request *http.Request, name string) string {
	values := request.Header.Values(name)
	if len(values) != 1 {
		return ""
	}
	return values[0]
}

func (server *Server) servePrivateRelay(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	if request.Method != "GET" || request.URL.Path != privateRelayPath {
		writeError(response, http.StatusForbidden, "access.denied")
		return
	}
	expected, status, code := server.inspectPrivateRoute(request)
	if status != 0 {
		writeError(response, status, code)
		return
	}
	identity, err := server.authenticateCredential(request)
	if err != nil {
		server.writeAuthenticationError(response, err)
		return
	}
	if identity.role != "device" || identity.redemption.RuntimeID != expected.RuntimeID {
		writeError(response, http.StatusForbidden, "access.denied")
		return
	}
	if !server.currentDeviceRoute(request.Context(), expected) {
		writeError(response, http.StatusConflict, "runtime.changed")
		return
	}
	server.serveConnection(response, request, identity, &expected)
}

func (server *Server) currentDeviceRoute(ctx context.Context, expected store.RuntimeRoute) bool {
	if server.routing == nil {
		return false
	}
	current, err := server.routing.Directory.LookupRuntimeRoute(ctx, expected.RuntimeID)
	if err != nil || current != expected {
		return false
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	host := server.hosts[expected.RuntimeID]
	return !server.draining && host != nil && !host.closing && host.runtimeEpoch == expected.RuntimeEpoch && host.connectionID == expected.ConnectionID
}

func (server *Server) proxyDevice(response http.ResponseWriter, request *http.Request, identity peer, route store.RuntimeRoute) {
	routing := server.routing
	if routing.ClientTLS == nil || route.Origin == "" || !store.ValidRelayOrigin(route.Origin) {
		writeError(response, http.StatusServiceUnavailable, "runtime.offline")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), deviceConnectionLife+handshakeTimeout)
	tunnel := &relayTunnel{ctx: ctx, cancel: cancel}
	server.mu.Lock()
	if server.draining || len(server.tunnels) >= routing.MaxProxyConnections {
		server.mu.Unlock()
		cancel()
		writeError(response, http.StatusServiceUnavailable, "rate.limited")
		return
	}
	server.tunnels[tunnel] = struct{}{}
	server.active.Add(1)
	server.mu.Unlock()
	defer func() {
		tunnel.close()
		server.mu.Lock()
		delete(server.tunnels, tunnel)
		server.mu.Unlock()
		server.active.Done()
	}()
	transport := routing.ownerTransport(route, func(connection net.Conn) error {
		tunnel.mu.Lock()
		defer tunnel.mu.Unlock()
		if tunnel.ctx.Err() != nil {
			return net.ErrClosed
		}
		tunnel.backClose = forceTransportCloser(connection)
		return nil
	})
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	raw, _ := json.Marshal(route)
	headers := http.Header{"Authorization": []string{"DSH-Ticket " + identity.ticket}}
	headers.Set(relayNodeHeader, routing.identity.NodeID)
	headers.Set(relayGenerationHeader, routing.identity.Generation)
	headers.Set(relayRouteHeader, base64.RawURLEncoding.EncodeToString(raw))
	back, reply, err := websocket.Dial(ctx, route.Origin+privateRelayPath, &websocket.DialOptions{HTTPClient: client, HTTPHeader: headers, Subprotocols: []string{protocolName}, CompressionMode: websocket.CompressionDisabled})
	if reply != nil && reply.Body != nil {
		_ = reply.Body.Close()
	}
	if err != nil {
		writeError(response, http.StatusServiceUnavailable, "runtime.offline")
		return
	}
	if !tunnel.bind(back, false) {
		return
	}
	back.SetReadLimit(maxFrameBytes)
	upgraded := &upgradeWriter{ResponseWriter: response}
	front, err := websocket.Accept(upgraded, request, &websocket.AcceptOptions{Subprotocols: []string{protocolName}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	tunnel.mu.Lock()
	tunnel.frontClose = forceTransportCloser(upgraded.transport)
	tunnel.mu.Unlock()
	if !tunnel.bind(front, true) {
		return
	}
	front.SetReadLimit(maxFrameBytes)
	if front.Subprotocol() != protocolName || back.Subprotocol() != protocolName {
		return
	}
	finished := make(chan struct{}, 2)
	copyMessages := func(source, target *websocket.Conn, direction int) {
		defer func() { finished <- struct{}{} }()
		for {
			typeID, body, err := source.Read(ctx)
			if err != nil || typeID != websocket.MessageText || len(body) > maxFrameBytes {
				return
			}
			started := time.Now()
			tunnel.inflight[direction].Store(int64(len(body)))
			write, stop := context.WithTimeout(ctx, 5*time.Second)
			err = target.Write(write, websocket.MessageText, body)
			stop()
			tunnel.inflight[direction].Store(0)
			server.metrics.TunnelTransit(direction, time.Since(started), err)
			if err != nil {
				return
			}
		}
	}
	go copyMessages(front, back, 0)
	go copyMessages(back, front, 1)
	<-finished
	tunnel.close()
	<-finished
}

func (tunnel *relayTunnel) bind(connection *websocket.Conn, front bool) bool {
	tunnel.mu.Lock()
	defer tunnel.mu.Unlock()
	if tunnel.ctx.Err() != nil {
		_ = connection.CloseNow()
		return false
	}
	if front {
		tunnel.front = connection
	} else {
		tunnel.back = connection
	}
	return true
}

func (tunnel *relayTunnel) close() {
	tunnel.cancel()
	tunnel.mu.Lock()
	front, back := tunnel.front, tunnel.back
	frontClose, backClose := tunnel.frontClose, tunnel.backClose
	tunnel.mu.Unlock()
	if frontClose != nil {
		_ = frontClose()
	}
	if backClose != nil {
		_ = backClose()
	}
	if front != nil {
		_ = front.CloseNow()
	}
	if back != nil {
		_ = back.CloseNow()
	}
}

func (routing *nodeRouting) ownerTransport(route store.RuntimeRoute, capture func(net.Conn) error) *http.Transport {
	clientTLS := routing.ClientTLS.Clone()
	previousVerify := clientTLS.VerifyConnection
	clientTLS.VerifyConnection = func(state tls.ConnectionState) error {
		if previousVerify != nil {
			if err := previousVerify(state); err != nil {
				return err
			}
		}
		if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
			return errors.New("relay: unverified owner")
		}
		node, err := RelayCertificateNode(state.PeerCertificates[0])
		if err != nil || node != route.NodeID {
			return errors.New("relay: wrong owner certificate")
		}
		return nil
	}
	transport := &http.Transport{TLSClientConfig: clientTLS, Proxy: nil,
		DialContext:         (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 3 * time.Second, MaxResponseHeaderBytes: 8 << 10}
	transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		dial, stop := context.WithTimeout(ctx, 3*time.Second)
		defer stop()
		connection, err := (&tls.Dialer{NetDialer: &net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}, Config: clientTLS}).DialContext(dial, network, address)
		if err != nil {
			return nil, err
		}
		if capture != nil {
			if err := capture(connection); err != nil {
				_ = connection.Close()
				return nil, err
			}
		}
		return connection, nil
	}
	return transport
}
