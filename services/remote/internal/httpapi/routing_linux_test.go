package httpapi_test

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/store"
	"dsh-mobile-ustc/services/remote/internal/testsupport"
	"github.com/coder/websocket"
	jose "github.com/go-jose/go-jose/v4"
)

type routingNodeFixture struct {
	id, address, privateOrigin, metrics, config, generation string
	certificate                                             tls.Certificate
	process                                                 *sharedProofProcess
}
type routingFixture struct {
	t         *testing.T
	ctx       context.Context
	db        *sql.DB
	origin    string
	nodes     map[string]*routingNodeFixture
	clients   map[string]*http.Client
	pairs     []*capacityPair
	ca        *testsupport.RelayCA
	issuerKey capacityKey
}

func newRoutingFixture(t *testing.T, count, maxProxies int) *routingFixture {
	t.Helper()
	binary := os.Getenv("REMOTE_TEST_SERVICE_BIN")
	if binary == "" {
		t.Skip("explicit production service binary required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	_, db := testsupport.PostgresDatabase(t)
	dsn, err := capacityDatabaseDSN(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &routingFixture{t: t, ctx: ctx, db: db, nodes: map[string]*routingNodeFixture{}, clients: map[string]*http.Client{}, ca: testsupport.NewRelayCA(t)}
	directory := t.TempDir()
	write := func(name string, body []byte) string {
		t.Helper()
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	write("relay-ca.pem", fixture.ca.PEM)
	issuerKey, err := newCapacityKey()
	if err != nil {
		t.Fatal(err)
	}
	fixture.issuerKey = issuerKey
	public, _ := json.Marshal(jose.JSONWebKey{Key: &issuerKey.private.PublicKey, KeyID: "routing-issuer", Algorithm: "ES256", Use: "sig"})
	jwks := append(append([]byte(`{"keys":[`), public...), []byte(`]}`)...)
	proxies := map[string]*httputil.ReverseProxy{}
	var reservations []net.Listener
	reserve := func() string {
		t.Helper()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		reservations = append(reservations, listener)
		t.Cleanup(func() { _ = listener.Close() })
		return listener.Addr().String()
	}
	for _, name := range []string{"a", "b"} {
		node := &routingNodeFixture{id: capacityID(), address: reserve(), privateOrigin: "https://" + reserve(), metrics: "http://" + reserve()}
		cert, key, pair := fixture.ca.Issue(t, node.id)
		node.certificate = pair
		write(name+".pem", cert)
		write(name+".key", key)
		config := map[string]any{"listen_addr": strings.TrimPrefix(node.privateOrigin, "https://"), "origin": node.privateOrigin, "ca_file": "relay-ca.pem", "certificate_file": name + ".pem", "key_file": name + ".key", "max_proxy_connections": maxProxies}
		raw, _ := json.Marshal(config)
		node.config = write(name+".json", raw)
		fixture.nodes[name] = node
		target, _ := url.Parse("http://" + node.address)
		proxy := httputil.NewSingleHostReverseProxy(target)
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.ResponseHeaderTimeout = 5 * time.Second
		proxy.Transport = transport
		t.Cleanup(transport.CloseIdleConnections)
		proxies[name] = proxy
	}
	ingress := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fixture/jwks" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(jwks)
			return
		}
		proxy := proxies[r.Header.Get("X-Fixture-Node")]
		if proxy == nil {
			http.Error(w, "unknown node", 400)
			return
		}
		r.Header.Del("X-Fixture-Node")
		proxy.ServeHTTP(w, r)
	}))
	ingress.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	ingress.StartTLS()
	t.Cleanup(ingress.Close)
	fixture.origin = ingress.URL
	for _, name := range []string{"a", "b"} {
		fixture.clients[name] = &http.Client{Transport: controlNodeTransport{ingress.Client().Transport, name}}
	}
	ca := write("issuer-ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ingress.Certificate().Raw}))
	issuer := ingress.URL + "/issuer"
	fixture.pairs, err = capacitySeed(ctx, db, count, issuer)
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range fixture.pairs {
		for _, role := range []string{"host", "phone"} {
			key, clientID := pair.phoneKey, "routing-phone"
			if role == "host" {
				key, clientID = pair.hostKey, "routing-host"
			}
			now := time.Now()
			token, err := capacitySign(issuerKey, "at+jwt", map[string]any{"iss": issuer, "sub": pair.user, "aud": "urn:routing", "client_id": clientID, "jti": capacityID(), "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "scope": "remote.access", "cnf": map[string]any{"jkt": key.jkt}}, map[jose.HeaderKey]any{"kid": "routing-issuer"})
			if err != nil {
				t.Fatal(err)
			}
			api := &capacityAPI{http: fixture.clients["a"], origin: ingress.URL, token: token, key: key}
			if role == "host" {
				pair.hostAPI = api
			} else {
				pair.phoneAPI = api
			}
		}
	}
	for _, listener := range reservations {
		_ = listener.Close()
	}
	for _, name := range []string{"a", "b"} {
		node := fixture.nodes[name]
		environment := []string{"PATH=" + os.Getenv("PATH"), "SSL_CERT_FILE=" + ca, "REMOTE_ISSUER=" + issuer, "REMOTE_AUDIENCE=urn:routing", "REMOTE_JWKS_URL=" + ingress.URL + "/fixture/jwks", "REMOTE_CLIENT_IDS=routing-host,routing-phone", "REMOTE_HOST_CLIENT_IDS=routing-host", "REMOTE_REQUIRED_SCOPES=remote.access", "REMOTE_PUBLIC_ORIGIN=" + ingress.URL, "REMOTE_DATABASE_URL=" + dsn, "REMOTE_LISTEN_ADDR=" + node.address, "REMOTE_RELAY_NODE_ID=" + node.id, "REMOTE_RELAY_CONFIG_FILE=" + node.config, "REMOTE_METRICS_LISTEN_ADDR=" + strings.TrimPrefix(node.metrics, "http://")}
		node.process = startSharedProofProcess(t, ctx, binary, environment, filepath.Join(directory, name+".log"))
		if err := capacityWait(ctx, 8*time.Second, func() (bool, error) {
			client := *fixture.clients[name]
			client.Timeout = time.Second
			response, err := client.Get(ingress.URL + "/readyz")
			if err != nil {
				return false, nil
			}
			_ = response.Body.Close()
			return response.StatusCode == 204, nil
		}); err != nil {
			raw, _ := os.ReadFile(node.process.log.Name())
			t.Fatalf("node %s readiness: %v %s", name, err, raw)
		}
		if err := db.QueryRowContext(ctx, `select generation::text from control_consumers where node_id=$1`, node.id).Scan(&node.generation); err != nil {
			t.Fatal(err)
		}
	}
	return fixture
}

func (f *routingFixture) host(pair *capacityPair, node string, capabilities ...string) *websocket.Conn {
	f.t.Helper()
	var challenge store.HostCredentialChallenge
	if err := pair.hostAPI.call(f.ctx, "POST", "/v1/host-credentials/challenges", map[string]any{}, &challenge, 201); err != nil {
		f.t.Fatal(err)
	}
	proof, err := capacitySign(pair.hostKey, "dsh-host-credential-proof+jwt", map[string]any{"iss": pair.installation, "aud": challenge.Audience, "challenge_id": challenge.ChallengeID, "nonce": challenge.Challenge, "iat": time.Now().Unix(), "jti": capacityID()}, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	var credential store.HostConnectionCredential
	if err := pair.hostAPI.call(f.ctx, "POST", "/v1/host-credentials", map[string]any{"challenge_id": challenge.ChallengeID, "proof": proof}, &credential, 201); err != nil {
		f.t.Fatal(err)
	}
	connection, err := capacityConnect(f.ctx, f.clients[node], f.origin, "installation", "DSH-Host "+credential.Credential, pair.hostKey, pair, capabilities...)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = connection.CloseNow() })
	approvalWrite(f.t, f.ctx, connection, capacityWire{V: 1, Type: "session.catalog", RequestID: capacityID(), RuntimeID: pair.runtime, RuntimeEpoch: pair.epoch, Payload: capacityPayload(map[string]any{"mode": "snapshot", "index": 0, "complete": true, "items": []store.SessionCatalogItem{{SessionID: pair.session, DSHSessionID: "capacity-session", WorkspaceID: &pair.workspace, State: "running", LastPersistedSeq: -1}}})})
	if ack := approvalRead(f.t, f.ctx, connection); ack.Type != "session.catalog.ack" {
		f.t.Fatal("catalog failed", ack.Type)
	}
	return connection
}

func (f *routingFixture) ticket(pair *capacityPair, extraActions ...string) store.RealtimeTicket {
	f.t.Helper()
	var ticket store.RealtimeTicket
	if err := pair.phoneAPI.call(f.ctx, "POST", "/v1/realtime/tickets", map[string]any{"runtime_id": pair.runtime, "scope": store.GrantScope{Actions: append([]string{"session.read"}, extraActions...), Workspaces: []string{pair.workspace}, Sessions: []string{pair.session}}}, &ticket, 201); err != nil {
		f.t.Fatal(err)
	}
	return ticket
}
func (f *routingFixture) phone(pair *capacityPair, node string) *websocket.Conn {
	f.t.Helper()
	ticket := f.ticket(pair)
	connection, err := capacityConnect(f.ctx, f.clients[node], f.origin, "device", "DSH-Ticket "+ticket.Token, pair.phoneKey, pair)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = connection.CloseNow() })
	return connection
}
func (f *routingFixture) route(pair *capacityPair) store.RuntimeRoute {
	f.t.Helper()
	var route store.RuntimeRoute
	if err := f.db.QueryRowContext(f.ctx, `select route.node_id::text,route.generation::text,node.relay_origin,route.runtime_id::text,route.runtime_epoch::text,route.connection_id::text from relay_runtime_routes route join control_consumers node on node.node_id=route.node_id where route.runtime_id=$1`, pair.runtime).Scan(&route.NodeID, &route.Generation, &route.Origin, &route.RuntimeID, &route.RuntimeEpoch, &route.ConnectionID); err != nil {
		f.t.Fatal(err)
	}
	return route
}
func (f *routingFixture) ping(connection *websocket.Conn) {
	f.t.Helper()
	approvalWrite(f.t, f.ctx, connection, map[string]any{"v": 1, "type": "ping", "payload": map[string]any{}})
	for i := 0; i < 8; i++ {
		frame := approvalRead(f.t, f.ctx, connection)
		if frame.Type == "pong" {
			return
		}
		if frame.Type != "session.unsubscribe" {
			f.t.Fatal("peer did not remain usable", frame.Type)
		}
	}
	f.t.Fatal("peer heartbeat did not settle")
}
func (f *routingFixture) closed(connection *websocket.Conn) {
	f.t.Helper()
	read, stop := context.WithTimeout(f.ctx, 4*time.Second)
	defer stop()
	for i := 0; i < 8; i++ {
		_, _, err := connection.Read(read)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				f.t.Fatal("stale transport did not close")
			}
			return
		}
	}
	f.t.Fatal("stale transport kept delivering frames")
}
func (f *routingFixture) snapshot(pair *capacityPair, host, phone *websocket.Conn) capacityWire {
	f.t.Helper()
	request := capacityID()
	approvalWrite(f.t, f.ctx, phone, capacityWire{V: 1, Type: "session.subscribe", RequestID: request, RuntimeID: pair.runtime, SessionID: pair.session, Payload: capacityPayload(map[string]any{"max_messages": 10})})
	if frame := approvalRead(f.t, f.ctx, phone); frame.Type != "session.subscribed" {
		f.t.Fatal("subscription missing", frame.Type)
	}
	forward, err := capacityRead(f.ctx, host)
	if err != nil || forward.Type != "session.subscribe" {
		f.t.Fatal("host did not receive subscription", forward.Type, err)
	}
	frame := capacityWire{V: 1, Type: "session.snapshot", RequestID: forward.RequestID, RuntimeID: pair.runtime, RuntimeEpoch: pair.epoch, SessionID: pair.session, SubscriptionID: forward.SubscriptionID, SyncID: capacityID(), Payload: capacityPayload(map[string]any{"cursor": -1, "records": []any{}, "has_more": false, "assistant": nil})}
	approvalWrite(f.t, f.ctx, host, frame)
	if result, err := capacityRead(f.ctx, phone); err != nil || result.Type != "session.snapshot" || result.SubscriptionID != forward.SubscriptionID {
		f.t.Fatal("cross-node snapshot failed", result.Type, err)
	}
	frame.Type = "assistant.start"
	attempt := capacityID()
	frame.Payload = capacityPayload(map[string]any{"type": "start", "attemptId": attempt, "revision": 1, "startedAfterSeq": -1, "turn": 0, "step": 0})
	approvalWrite(f.t, f.ctx, host, frame)
	if result := approvalRead(f.t, f.ctx, phone); result.Type != "assistant.start" {
		f.t.Fatal("assistant start missing", result.Type)
	}
	frame.Type = "assistant.chunk"
	frame.Payload = capacityPayload(map[string]any{"type": "chunk", "attemptId": attempt, "revision": 1, "index": 0, "time": time.Now().UnixMilli(), "chunk": map[string]any{"type": "text-delta", "index": 0, "text": "PRIVATE_CROSS_NODE_BODY_MARKER"}})
	approvalWrite(f.t, f.ctx, host, frame)
	if result, err := capacityRead(f.ctx, phone); err != nil || result.Type != "assistant.chunk" || string(result.Payload) != string(frame.Payload) {
		f.t.Fatal("stream body changed across nodes", result.Type, err)
	}
	return frame
}

func TestProductionRoutingCrossesNodesRevokesAndFencesHostMigration(t *testing.T) {
	f := newRoutingFixture(t, 2, 4)
	pair := f.pairs[0]
	host := f.host(pair, "a")
	phone := f.phone(pair, "b")
	f.snapshot(pair, host, phone)
	metrics, raw, err := capacityMetrics(http.DefaultClient, f.nodes["b"].metrics)
	if err != nil || capacityMetric(metrics, "dsh_remote_relay_proxy_tunnels", nil) != 1 || strings.Contains(raw, "PRIVATE_CROSS_NODE_BODY_MARKER") || strings.Contains(raw, pair.runtime) {
		t.Fatal("ingress tunnel observation incorrect", err)
	}
	owner, _, err := capacityMetrics(http.DefaultClient, f.nodes["a"].metrics)
	if err != nil || capacityMetric(owner, "dsh_remote_relay_connections", map[string]string{"role": "device", "phase": "active"}) != 1 {
		t.Fatal("device was not routed to owning process", err)
	}
	// A resource from another host must not cross the existing private tunnel.
	approvalWrite(t, f.ctx, phone, capacityWire{V: 1, Type: "session.subscribe", RequestID: capacityID(), RuntimeID: pair.runtime, SessionID: f.pairs[1].session, Payload: capacityPayload(map[string]any{"max_messages": 10})})
	if frame := approvalRead(t, f.ctx, phone); frame.Type != "error" {
		t.Fatal("foreign session was admitted", frame.Type)
	}
	pair.epoch = capacityID()
	replacement := f.host(pair, "b")
	newRoute := f.route(pair)
	if newRoute.NodeID != f.nodes["b"].id {
		t.Fatal("host migration did not replace directory")
	}
	f.closed(host)
	f.closed(phone)
	if current := f.route(pair); current != newRoute {
		t.Fatal("old host cleanup erased successor")
	}
	reconnected := f.phone(pair, "a")
	f.snapshot(pair, replacement, reconnected)
	// Revocation enters through the other public process and must reach the
	// actual authorization owner before any subsequent content can be routed.
	pair.phoneAPI.http = f.clients["a"]
	if err := pair.phoneAPI.call(f.ctx, "DELETE", "/v1/devices/"+pair.device, nil, nil, 200); err != nil {
		t.Fatal(err)
	}
	if frame := approvalRead(t, f.ctx, reconnected); frame.Type != "access.revoked" {
		t.Fatal("cross-node revoke omitted", frame.Type)
	}
	f.closed(reconnected)
	f.ping(replacement)
}

func TestProductionRoutingPrivateAdmissionAndProxyBudget(t *testing.T) {
	f := newRoutingFixture(t, 2, 1)
	pair := f.pairs[0]
	f.host(pair, "a")
	route := f.route(pair)
	ticket := f.ticket(pair)
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: f.ca.Roots, Certificates: []tls.Certificate{f.nodes["b"].certificate}}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	request := func(node, generation string, expected store.RuntimeRoute, token string) *http.Request {
		t.Helper()
		raw, _ := json.Marshal(expected)
		req, err := http.NewRequestWithContext(f.ctx, "GET", route.Origin+"/internal/relay/v1/device", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "DSH-Ticket "+token)
		req.Header.Set("X-DSH-Relay-Node", node)
		req.Header.Set("X-DSH-Relay-Generation", generation)
		req.Header.Set("X-DSH-Relay-Route", base64.RawURLEncoding.EncodeToString(raw))
		return req
	}
	for _, check := range []struct {
		name, node, generation string
		route                  store.RuntimeRoute
		token                  string
		status                 int
	}{
		{"forged node", f.nodes["a"].id, f.nodes["b"].generation, route, ticket.Token, 403},
		{"old generation", f.nodes["b"].id, capacityID(), route, ticket.Token, 503},
		{"wrong connection", f.nodes["b"].id, f.nodes["b"].generation, func() store.RuntimeRoute { r := route; r.ConnectionID = capacityID(); return r }(), ticket.Token, 409},
		{"foreign ticket", f.nodes["b"].id, f.nodes["b"].generation, route, f.ticket(f.pairs[1]).Token, 403},
	} {
		t.Run(check.name, func(t *testing.T) {
			response, err := client.Do(request(check.node, check.generation, check.route, check.token))
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if response.StatusCode != check.status {
				t.Fatal("unexpected admission status", response.StatusCode)
			}
		})
	}
	noCertificate := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: f.ca.Roots}}, Timeout: 3 * time.Second}
	if response, err := noCertificate.Do(request(f.nodes["b"].id, f.nodes["b"].generation, route, ticket.Token)); err == nil {
		_ = response.Body.Close()
		t.Fatal("private listener accepted missing client certificate")
	}
	noCertificate.CloseIdleConnections()
	// HTTP uses the same node/generation gate and an explicit route allowlist.
	for _, check := range []struct {
		path, generation string
		status           int
	}{
		{"/v1/devices", f.nodes["b"].generation, 403},
		{"/v1/files/" + capacityID(), capacityID(), 503},
		{"/v1/files/" + capacityID(), f.nodes["b"].generation, 404}, // Files disabled: the normal owner router applies.
	} {
		req := request(f.nodes["b"].id, check.generation, route, ticket.Token)
		req.URL.Path = "/internal/relay/v1/http"
		req.Header.Set("X-DSH-Relay-Original-Path", check.path)
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != check.status {
			t.Fatal("private HTTP route bypassed owner admission", response.StatusCode)
		}
	}
	// A correct CA/hostname with the wrong node URI must fail before the ticket
	// is sent, even if directory metadata points at that other TLS endpoint.
	if _, err := f.db.ExecContext(f.ctx, `update control_consumers set relay_origin=$2 where node_id=$1`, f.nodes["a"].id, f.nodes["b"].privateOrigin); err != nil {
		t.Fatal(err)
	}
	if connection, err := capacityConnect(f.ctx, f.clients["b"], f.origin, "device", "DSH-Ticket "+ticket.Token, pair.phoneKey, pair); err == nil {
		_ = connection.CloseNow()
		t.Fatal("wrong owner certificate accepted")
	}
	if _, err := f.db.ExecContext(f.ctx, `update control_consumers set relay_origin=$2 where node_id=$1`, f.nodes["a"].id, route.Origin); err != nil {
		t.Fatal(err)
	}
	phone, err := capacityConnect(f.ctx, f.clients["b"], f.origin, "device", "DSH-Ticket "+ticket.Token, pair.phoneKey, pair)
	if err != nil {
		t.Fatal("rejected attempts consumed ticket", err)
	}
	t.Cleanup(func() { _ = phone.CloseNow() })
	second := f.ticket(pair)
	if connection, err := capacityConnect(f.ctx, f.clients["b"], f.origin, "device", "DSH-Ticket "+second.Token, pair.phoneKey, pair); err == nil {
		_ = connection.CloseNow()
		t.Fatal("proxy connection budget ignored")
	}
	f.ping(phone)
	_ = phone.CloseNow()
	if err := capacityWait(f.ctx, 3*time.Second, func() (bool, error) {
		families, _, err := capacityMetrics(http.DefaultClient, f.nodes["b"].metrics)
		return capacityMetric(families, "dsh_remote_relay_proxy_tunnels", nil) == 0, err
	}); err != nil {
		t.Fatal(err)
	}
	connection, err := capacityConnect(f.ctx, f.clients["b"], f.origin, "device", "DSH-Ticket "+second.Token, pair.phoneKey, pair)
	if err != nil {
		t.Fatal("budget rejection consumed ticket or leaked slot", err)
	}
	_ = connection.CloseNow()
}

func TestProductionRoutingIngressDrainPreservesHostAndForcesResync(t *testing.T) {
	f := newRoutingFixture(t, 1, 2)
	pair := f.pairs[0]
	host := f.host(pair, "a")
	phone := f.phone(pair, "b")
	f.snapshot(pair, host, phone)
	f.nodes["b"].process.stop(t)
	f.closed(phone)
	f.ping(host)
	reconnected := f.phone(pair, "a")
	f.snapshot(pair, host, reconnected)
}
