package httpapi_test

import (
	"context"
	"crypto/tls"
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
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/store"
	"dsh-mobile-ustc/services/remote/internal/testsupport"
	"github.com/coder/websocket"
	jose "github.com/go-jose/go-jose/v4"
)

type controlNodeTransport struct {
	base http.RoundTripper
	node string
}

func (transport controlNodeTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	copy := request.Clone(request.Context())
	copy.Header = request.Header.Clone()
	copy.Header.Set("X-Fixture-Node", transport.node)
	return transport.base.RoundTrip(copy)
}

func TestProductionControlFanoutReachesBothProcessesAndReplaysOfflineNode(t *testing.T) {
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
	issuerKey, err := newCapacityKey()
	if err != nil {
		t.Fatal(err)
	}
	public, _ := json.Marshal(jose.JSONWebKey{Key: &issuerKey.private.PublicKey, KeyID: "control-issuer", Algorithm: "ES256", Use: "sig"})
	jwks := append(append([]byte(`{"keys":[`), public...), []byte(`]}`)...)
	reserve := func() net.Listener {
		t.Helper()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		return listener
	}
	reserveA, reserveB := reserve(), reserve()
	defer reserveA.Close()
	defer reserveB.Close()
	addresses := map[string]string{"a": reserveA.Addr().String(), "b": reserveB.Addr().String()}
	nodes := map[string]string{"a": capacityID(), "b": capacityID()}
	proxies := map[string]*httputil.ReverseProxy{}
	for node, address := range addresses {
		target, _ := url.Parse("http://" + address)
		proxy := httputil.NewSingleHostReverseProxy(target)
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.ResponseHeaderTimeout = 5 * time.Second
		proxy.Transport = transport
		t.Cleanup(transport.CloseIdleConnections)
		proxies[node] = proxy
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
	clients := map[string]*http.Client{}
	for _, node := range []string{"a", "b"} {
		clients[node] = &http.Client{Transport: controlNodeTransport{ingress.Client().Transport, node}}
	}
	issuer := ingress.URL + "/issuer"
	pairs, err := capacitySeed(ctx, db, 3, issuer)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	ca := filepath.Join(directory, "issuer-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ingress.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	environment := func(node string) []string {
		return []string{"PATH=" + os.Getenv("PATH"), "SSL_CERT_FILE=" + ca, "REMOTE_ISSUER=" + issuer, "REMOTE_AUDIENCE=urn:control-fanout", "REMOTE_JWKS_URL=" + ingress.URL + "/fixture/jwks", "REMOTE_CLIENT_IDS=control-phone", "REMOTE_REQUIRED_SCOPES=remote.access", "REMOTE_PUBLIC_ORIGIN=" + ingress.URL, "REMOTE_DATABASE_URL=" + dsn, "REMOTE_LISTEN_ADDR=" + addresses[node], "REMOTE_RELAY_NODE_ID=" + nodes[node]}
	}
	_ = reserveA.Close()
	_ = reserveB.Close()
	a := startSharedProofProcess(t, ctx, binary, environment("a"), filepath.Join(directory, "node-a.log"))
	b := startSharedProofProcess(t, ctx, binary, environment("b"), filepath.Join(directory, "node-b.log"))
	waitReady := func(node string) {
		t.Helper()
		client := *clients[node]
		client.Timeout = time.Second
		if err := capacityWait(ctx, 8*time.Second, func() (bool, error) {
			response, err := client.Get(ingress.URL + "/readyz")
			if err != nil {
				return false, nil
			}
			_ = response.Body.Close()
			return response.StatusCode == 204, nil
		}); err != nil {
			t.Fatal("node failed readiness", node)
		}
	}
	waitReady("a")
	waitReady("b")
	for _, pair := range pairs {
		now := time.Now()
		token, err := capacitySign(issuerKey, "at+jwt", map[string]any{"iss": issuer, "sub": pair.user, "aud": "urn:control-fanout", "client_id": "control-phone", "jti": capacityID(), "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "scope": "remote.access", "cnf": map[string]any{"jkt": pair.phoneKey.jkt}}, map[jose.HeaderKey]any{"kid": "control-issuer"})
		if err != nil {
			t.Fatal(err)
		}
		pair.phoneAPI = &capacityAPI{http: clients["a"], origin: ingress.URL, token: token, key: pair.phoneKey}
	}
	connect := func(pair *capacityPair, node string) *websocket.Conn {
		t.Helper()
		var ticket store.RealtimeTicket
		scope := store.GrantScope{Actions: []string{"session.read"}, Workspaces: []string{pair.workspace}, Sessions: []string{pair.session}}
		if err := pair.phoneAPI.call(ctx, "POST", "/v1/realtime/tickets", map[string]any{"runtime_id": pair.runtime, "scope": scope}, &ticket, 201); err != nil {
			t.Fatal(err)
		}
		connection, err := capacityConnect(ctx, clients[node], ingress.URL, "device", "DSH-Ticket "+ticket.Token, pair.phoneKey, pair)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = connection.CloseNow() })
		return connection
	}
	left, right, sibling := connect(pairs[0], "a"), connect(pairs[0], "b"), connect(pairs[1], "b")
	ping := func(connection *websocket.Conn) {
		t.Helper()
		approvalWrite(t, ctx, connection, map[string]any{"v": 1, "type": "ping", "payload": map[string]any{}})
		if frame := approvalRead(t, ctx, connection); frame.Type != "pong" {
			t.Fatal("unrelated connection did not remain usable")
		}
	}
	ping(left)
	ping(right)
	ping(sibling)
	started := time.Now()
	if err := pairs[0].phoneAPI.call(ctx, "DELETE", "/v1/devices/"+pairs[0].device, nil, nil, 200); err != nil {
		t.Fatal(err)
	}
	for _, connection := range []*websocket.Conn{left, right} {
		frame := approvalRead(t, ctx, connection)
		if frame.Type != "access.revoked" {
			t.Fatal("node omitted ordered invalidation", frame.Type)
		}
		read, stop := context.WithTimeout(ctx, time.Second)
		_, _, err := connection.Read(read)
		stop()
		if err == nil || errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("revoked socket stayed open")
		}
	}
	if time.Since(started) > 5*time.Second {
		t.Fatal("cross-node revoke exceeded target window")
	}
	// Per-node completion includes a compacted covered snapshot, not merely the
	// legacy shared published_at marker. Both consumers existed before revoke.
	waitCovered := func(device string, expected int) {
		t.Helper()
		if err := capacityWait(ctx, 5*time.Second, func() (bool, error) {
			var count int
			err := db.QueryRowContext(ctx, `select count(*) from control_consumers consumer where consumer.node_id in($1,$2) and exists(
            select 1 from control_outbox event where event.topic='device.revoked' and event.payload->>'device_id'=$3 and
              (pg_visible_in_snapshot(event.producer_xid,consumer.coverage) or exists(select 1 from control_event_acks ack where ack.node_id=consumer.node_id and ack.event_id=event.id)))`, nodes["a"], nodes["b"], device).Scan(&count)
			return count == expected, err
		}); err != nil {
			t.Fatal("independent consumer delivery was not acknowledged", err)
		}
	}
	waitCovered(pairs[0].device, 2)
	// Respect the protocol heartbeat interval while checking the unaffected peer.
	timer := time.NewTimer(1100 * time.Millisecond)
	select {
	case <-timer.C:
	case <-ctx.Done():
		timer.Stop()
		t.Fatal(ctx.Err())
	}
	ping(sibling)
	_ = sibling.CloseNow()
	proxies["b"].Transport.(*http.Transport).CloseIdleConnections()
	b.stop(t)
	if err := pairs[1].phoneAPI.call(ctx, "DELETE", "/v1/devices/"+pairs[1].device, nil, nil, 200); err != nil {
		t.Fatal(err)
	}
	var stillUnseen bool
	if err := db.QueryRowContext(ctx, `select not pg_visible_in_snapshot(event.producer_xid,consumer.coverage) from control_consumers consumer join control_outbox event on event.topic='device.revoked' and event.payload->>'device_id'=$2 where consumer.node_id=$1`, nodes["b"], pairs[1].device).Scan(&stillUnseen); err != nil || !stillUnseen {
		t.Fatal("offline delivery was pre-acknowledged", err)
	}
	restarted := startSharedProofProcess(t, ctx, binary, environment("b"), filepath.Join(directory, "node-b-restarted.log"))
	waitReady("b")
	waitCovered(pairs[1].device, 2)
	if err := pairs[1].phoneAPI.call(ctx, "POST", "/v1/realtime/tickets", map[string]any{"runtime_id": pairs[1].runtime, "scope": store.GrantScope{Actions: []string{"session.read"}, Workspaces: []string{pairs[1].workspace}, Sessions: []string{pairs[1].session}}}, nil, 403); err != nil {
		t.Fatal("revoked device regained authority", err)
	}
	fenced := connect(pairs[2], "b")
	if _, err := db.ExecContext(ctx, `update control_consumers set generation=gen_random_uuid(),lease_until=clock_timestamp()-interval '1 second' where node_id=$1`, nodes["b"]); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-restarted.done:
		restarted.stopped = true
		_ = restarted.log.Close()
		if err == nil {
			t.Fatal("fenced node reported a successful exit")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fenced node kept serving")
	}
	read, stop := context.WithTimeout(ctx, time.Second)
	_, _, err = fenced.Read(read)
	stop()
	if err == nil {
		read, stop = context.WithTimeout(ctx, time.Second)
		_, _, err = fenced.Read(read)
		stop()
	}
	if err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("fenced node left upgraded transport alive")
	}
	for _, proxy := range proxies {
		proxy.Transport.(*http.Transport).CloseIdleConnections()
	}
	a.stop(t)
	restarted.stop(t)
	for _, path := range []string{"node-a.log", "node-b.log", "node-b-restarted.log"} {
		raw, err := os.ReadFile(filepath.Join(directory, path))
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) > 1<<20 {
			t.Fatal("unbounded control logs")
		}
	}
	t.Log("Both production processes independently applied/acknowledged one device revoke, preserved an unrelated peer, replayed an offline revoke and stopped admission/transports after generation fencing")
}
