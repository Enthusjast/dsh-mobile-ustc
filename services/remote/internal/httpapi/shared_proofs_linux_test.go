package httpapi_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/testsupport"
	jose "github.com/go-jose/go-jose/v4"
)

type sharedProofProcess struct {
	command *exec.Cmd
	done    chan error
	log     *os.File
	stopped bool
}

func startSharedProofProcess(t *testing.T, ctx context.Context, binary string, environment []string, path string) *sharedProofProcess {
	t.Helper()
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, binary)
	command.Env = environment
	command.Stdout, command.Stderr = file, file
	if err := command.Start(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	process := &sharedProofProcess{command: command, done: make(chan error, 1), log: file}
	go func() { process.done <- command.Wait() }()
	t.Cleanup(func() { process.stop(t) })
	return process
}

func (process *sharedProofProcess) stop(t *testing.T) {
	t.Helper()
	if process.stopped {
		return
	}
	process.stopped = true
	_ = process.command.Process.Signal(syscall.SIGTERM)
	select {
	case err := <-process.done:
		if err != nil {
			if raw, readErr := os.ReadFile(process.log.Name()); readErr == nil {
				for _, line := range strings.Split(string(raw), "\n") {
					if strings.Contains(line, "remote service shutdown failed") || strings.Contains(line, "remote realtime drain failed") {
						t.Log(line)
					}
				}
			}
			t.Error("shared-proof process did not stop cleanly", err)
		}
	case <-time.After(6 * time.Second):
		_ = process.command.Process.Kill()
		<-process.done
		t.Error("shared-proof process shutdown timed out")
	}
	_ = process.log.Close()
}

func TestProductionProofStateCrossesProcessesAndSurvivesRestart(t *testing.T) {
	binary := os.Getenv("REMOTE_TEST_SERVICE_BIN")
	if binary == "" {
		t.Skip("explicit production service binary required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
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
	proofKey, err := newCapacityKey()
	if err != nil {
		t.Fatal(err)
	}
	public, _ := json.Marshal(jose.JSONWebKey{Key: &issuerKey.private.PublicKey, KeyID: "shared-proof-issuer", Algorithm: "ES256", Use: "sig"})
	jwks := append(append([]byte(`{"keys":[`), public...), []byte(`]}`)...)
	reserve := func() net.Listener {
		t.Helper()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		return listener
	}
	a, b := reserve(), reserve()
	defer a.Close()
	defer b.Close()
	addresses := map[string]string{"a": a.Addr().String(), "b": b.Addr().String()}
	proxies := map[string]*httputil.ReverseProxy{}
	for name, address := range addresses {
		target, _ := url.Parse("http://" + address)
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
			http.Error(w, "unknown fixture node", 400)
			return
		}
		r.Header.Del("X-Fixture-Node")
		proxy.ServeHTTP(w, r)
	}))
	ingress.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	ingress.StartTLS()
	defer ingress.Close()
	client := ingress.Client()
	client.Timeout = 6 * time.Second
	defer client.CloseIdleConnections()
	issuer := ingress.URL + "/issuer"
	subject, user := capacityID(), capacityID()
	if _, err := db.ExecContext(ctx, `insert into users(id,issuer,subject) values($1,$2,$3)`, user, issuer, subject); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	ca := filepath.Join(directory, "issuer-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ingress.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	environment := func(node string) []string {
		return []string{"PATH=" + os.Getenv("PATH"), "SSL_CERT_FILE=" + ca, "REMOTE_ISSUER=" + issuer, "REMOTE_AUDIENCE=urn:shared-proof", "REMOTE_JWKS_URL=" + ingress.URL + "/fixture/jwks", "REMOTE_CLIENT_IDS=proof-phone", "REMOTE_REQUIRED_SCOPES=remote.access", "REMOTE_PUBLIC_ORIGIN=" + ingress.URL, "REMOTE_DATABASE_URL=" + dsn, "REMOTE_LISTEN_ADDR=" + addresses[node]}
	}
	_ = a.Close()
	_ = b.Close()
	first := startSharedProofProcess(t, ctx, binary, environment("a"), filepath.Join(directory, "node-a.log"))
	second := startSharedProofProcess(t, ctx, binary, environment("b"), filepath.Join(directory, "node-b.log"))
	waitReady := func(node string) {
		t.Helper()
		if err := capacityWait(ctx, 8*time.Second, func() (bool, error) {
			request, _ := http.NewRequestWithContext(ctx, "GET", ingress.URL+"/readyz", nil)
			request.Header.Set("X-Fixture-Node", node)
			response, err := client.Do(request)
			if err != nil {
				return false, nil
			}
			_ = response.Body.Close()
			return response.StatusCode == 204, nil
		}); err != nil {
			t.Fatal("fixture service did not become ready", node)
		}
	}
	waitReady("a")
	waitReady("b")
	now := time.Now()
	token, err := capacitySign(issuerKey, "at+jwt", map[string]any{"iss": issuer, "sub": subject, "aud": "urn:shared-proof", "client_id": "proof-phone", "jti": capacityID(), "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "scope": "remote.access", "cnf": map[string]any{"jkt": proofKey.jkt}}, map[jose.HeaderKey]any{"kid": "shared-proof-issuer"})
	if err != nil {
		t.Fatal(err)
	}
	makeProof := func(jti, nonce string) string {
		t.Helper()
		ath := sha256.Sum256([]byte(token))
		proof, err := capacitySign(proofKey, "dpop+jwt", map[string]any{"htm": "GET", "htu": ingress.URL + "/v1/me", "iat": time.Now().Unix(), "ath": base64.RawURLEncoding.EncodeToString(ath[:]), "jti": jti, "nonce": nonce}, map[jose.HeaderKey]any{"jwk": proofKey.public})
		if err != nil {
			t.Fatal(err)
		}
		return proof
	}
	type response struct {
		status int
		nonce  string
		err    error
		user   string
	}
	call := func(node, proof string) response {
		request, err := http.NewRequestWithContext(ctx, "GET", ingress.URL+"/v1/me", nil)
		if err != nil {
			return response{err: err}
		}
		request.Header.Set("X-Fixture-Node", node)
		request.Header.Set("Authorization", "DPoP "+token)
		request.Header.Set("DPoP", proof)
		reply, err := client.Do(request)
		if err != nil {
			return response{err: errors.New("fixture TLS request failed")}
		}
		raw, readErr := io.ReadAll(io.LimitReader(reply.Body, 64<<10))
		_ = reply.Body.Close()
		var value struct {
			Data struct {
				User string `json:"user_id"`
			} `json:"data"`
		}
		_ = json.Unmarshal(raw, &value)
		return response{reply.StatusCode, reply.Header.Get("DPoP-Nonce"), readErr, value.Data.User}
	}
	challenge := call("a", makeProof(capacityID(), ""))
	if challenge.err != nil || challenge.status != 401 || !auth.ValidProofThumbprint(challenge.nonce) {
		t.Fatal("node a did not issue a shared challenge")
	}
	proof := makeProof(capacityID(), challenge.nonce)
	accepted := call("b", proof)
	if accepted.err != nil || accepted.status != 200 || accepted.user != user || !auth.ValidProofThumbprint(accepted.nonce) {
		t.Fatal("node b could not consume node a's challenge")
	}
	if replay := call("a", proof); replay.err != nil || replay.status != 401 {
		t.Fatal("cross-node replay accepted")
	}
	concurrentProof := makeProof(capacityID(), accepted.nonce)
	results := make(chan response, 16)
	var group sync.WaitGroup
	for index := range 16 {
		group.Add(1)
		go func() {
			defer group.Done()
			node := "a"
			if index%2 != 0 {
				node = "b"
			}
			results <- call(node, concurrentProof)
		}()
	}
	group.Wait()
	close(results)
	winners := 0
	var next string
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.status == 200 {
			winners++
			next = result.nonce
		} else if result.status != 401 {
			t.Fatal("concurrent proof returned unexpected status", result.status)
		}
	}
	if winners != 1 {
		t.Fatal("proof reached multiple process handlers", winners)
	}
	// The fixture owns idle backend transports, including speculative dials;
	// retire them before the process so they cannot hold a fresh socket open.
	proxies["a"].Transport.(*http.Transport).CloseIdleConnections()
	first.stop(t)
	restarted := startSharedProofProcess(t, ctx, binary, environment("a"), filepath.Join(directory, "node-a-restarted.log"))
	_ = restarted
	waitReady("a")
	if replay := call("a", concurrentProof); replay.err != nil || replay.status != 401 {
		t.Fatal("restarted process forgot replay state")
	}
	validAfterRestart := makeProof(capacityID(), next)
	fresh := call("a", validAfterRestart)
	if fresh.err != nil || fresh.status != 200 {
		t.Fatal("unspent challenge did not survive process restart")
	}
	// A blocked authoritative bucket must return 503, without consuming the
	// proof or falling back to process memory. Retry only after releasing it.
	scope, err := auth.ProofScope(issuer, "urn:shared-proof", ingress.URL)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(proofKey.jkt))
	block, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer block.Rollback()
	var count int
	if err := block.QueryRowContext(ctx, `select entry_count from dpop_proof_buckets where scope_sha256=$1 and bucket=$2 for update`, scope[:], int(digest[0])).Scan(&count); err != nil {
		t.Fatal(err)
	}
	blockedProof := makeProof(capacityID(), fresh.nonce)
	started := time.Now()
	unavailable := call("b", blockedProof)
	if unavailable.err != nil || unavailable.status != 503 || unavailable.nonce != "" || time.Since(started) > 5*time.Second {
		t.Fatal("storage wait did not fail closed within its deadline", unavailable.status, unavailable.err)
	}
	_ = block.Rollback()
	if retried := call("a", blockedProof); retried.err != nil || retried.status != 200 {
		t.Fatal("failed storage attempt spent nonce or jti")
	}
	for _, proxy := range proxies {
		proxy.Transport.(*http.Transport).CloseIdleConnections()
	}
	second.stop(t)
	restarted.stop(t)
	t.Log("Two production processes shared nonce/jti consumption, accepted one racing request, retained state across restart and returned bounded 503 without spending proof on authoritative storage timeout")
}
