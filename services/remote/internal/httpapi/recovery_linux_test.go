package httpapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/store"
	"dsh-mobile-ustc/services/remote/internal/testsupport"
	jose "github.com/go-jose/go-jose/v4"
)

type recoveryRetargetTransport struct {
	base    http.RoundTripper
	address string
}

func (transport recoveryRetargetTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	copy := request.Clone(request.Context())
	value := *request.URL
	copy.URL = &value
	copy.URL.Scheme, copy.URL.Host = "http", transport.address
	return transport.base.RoundTrip(copy)
}

func TestProductionRecoveryCLIRequiresFreshEpochAndAuthorityBeforeServing(t *testing.T) {
	f := newRoutingFixture(t, 1, 2)
	pair := f.pairs[0]
	binary := os.Getenv("REMOTE_TEST_SERVICE_BIN")
	sourceHost := f.host(pair, "a")
	sourcePhone := f.phone(pair, "b")
	ctx, db, dsn := testsupport.RestoredPostgresDatabase(t, f.db)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	directory := t.TempDir()
	operation, epoch := capacityID(), capacityID()
	base := []string{}
	for _, item := range f.nodes["a"].process.command.Env {
		name, _, _ := strings.Cut(item, "=")
		switch name {
		case "PATH", "SSL_CERT_FILE", "REMOTE_ISSUER", "REMOTE_AUDIENCE", "REMOTE_JWKS_URL", "REMOTE_CLIENT_IDS", "REMOTE_HOST_CLIENT_IDS", "REMOTE_REQUIRED_SCOPES", "REMOTE_PUBLIC_ORIGIN":
			base = append(base, item)
		}
	}
	environment := func(epoch string) []string {
		return append(append([]string{}, base...), "REMOTE_DATABASE_URL="+dsn, "REMOTE_LISTEN_ADDR="+address, "REMOTE_RELAY_NODE_ID="+f.nodes["a"].id, "REMOTE_DATABASE_EPOCH="+epoch)
	}
	rejected := func(epoch string) {
		t.Helper()
		attempt, stop := context.WithTimeout(ctx, 3*time.Second)
		defer stop()
		command := exec.CommandContext(attempt, binary)
		command.Env = environment(epoch)
		raw, err := command.CombinedOutput()
		if err == nil || errors.Is(attempt.Err(), context.DeadlineExceeded) || !strings.Contains(string(raw), "database recovery") {
			t.Fatal("service admitted an unready/mismatched recovery")
		}
	}
	runCLI := func(expect bool, arguments ...string) []byte {
		t.Helper()
		command := exec.CommandContext(ctx, binary, append([]string{"recovery"}, arguments...)...)
		command.Env = environment(epoch)
		raw, err := command.CombinedOutput()
		if expect && err != nil {
			t.Fatalf("recovery CLI failed: %s", raw)
		}
		if !expect && err == nil {
			t.Fatal("invalid recovery CLI input succeeded")
		}
		return raw
	}
	rejected(epoch) // external epoch set before the restored DB can be exposed
	var initial store.RecoveryState
	if json.Unmarshal(runCLI(true, "status"), &initial) != nil || initial.Epoch != store.OriginalDatabaseEpoch {
		t.Fatal("status could not reconcile actual restored epoch")
	}
	var prepared store.RecoveryRun
	if json.Unmarshal(runCLI(true, "quarantine", "--recovery-id", operation, "--expected-epoch", store.OriginalDatabaseEpoch, "--epoch", epoch), &prepared) != nil || prepared.Phase != "quarantined" {
		t.Fatal("CLI did not atomically quarantine restore")
	}
	rejected(epoch)
	var org string
	if err := db.QueryRowContext(ctx, `select org_id::text from hosts where id=$1`, pair.host).Scan(&org); err != nil {
		t.Fatal(err)
	}
	authority := store.RecoveryAuthority{Version: 1, Complete: true, RecoveryID: operation, DatabaseEpoch: epoch, Issuer: f.origin + "/issuer", CapturedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(5 * time.Minute).UTC(), Users: []store.RecoveryUser{{Subject: pair.user, Status: "active", Memberships: []store.RecoveryMembership{{OrganizationID: org, Role: "member"}}}}}
	raw, _ := json.Marshal(authority)
	manifest := filepath.Join(directory, "authority.json")
	if err := os.WriteFile(manifest, raw, 0644); err != nil {
		t.Fatal(err)
	}
	runCLI(false, "release", "--recovery-id", operation, "--authority-file", manifest)
	if err := os.Chmod(manifest, 0600); err != nil {
		t.Fatal(err)
	}
	var released store.RecoveryRun
	if json.Unmarshal(runCLI(true, "release", "--recovery-id", operation, "--authority-file", manifest), &released) != nil || released.Phase != "ready" {
		t.Fatal("CLI did not release fresh authority")
	}
	rejected(store.OriginalDatabaseEpoch)
	process := startSharedProofProcess(t, ctx, binary, environment(epoch), filepath.Join(directory, "recovered.log"))
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: recoveryRetargetTransport{transport, address}, Timeout: 3 * time.Second}
	if err := capacityWait(ctx, 5*time.Second, func() (bool, error) {
		response, err := client.Get(f.origin + "/readyz")
		if err != nil {
			return false, nil
		}
		_ = response.Body.Close()
		return response.StatusCode == 204, nil
	}); err != nil {
		t.Fatal("released service never became ready", err)
	}
	old := *pair.phoneAPI
	old.http = client
	if response, err := old.once(ctx, "GET", "/v1/me", nil, pair.phoneKey); err != nil || response.status != 401 {
		t.Fatal("pre-recovery access token authenticated", response.status, err)
	}
	state, err := (&store.Postgres{DB: db}).RecoveryStatus(ctx)
	if err != nil || state.TokenNotBefore == nil {
		t.Fatal(err)
	}
	iat := state.TokenNotBefore.Unix()
	token, err := capacitySign(f.issuerKey, "at+jwt", map[string]any{"iss": authority.Issuer, "sub": pair.user, "aud": "urn:routing", "client_id": "routing-phone", "jti": capacityID(), "iat": iat, "exp": iat + 300, "scope": "remote.access", "cnf": map[string]any{"jkt": pair.phoneKey.jkt}}, map[jose.HeaderKey]any{"kid": "routing-issuer"})
	if err != nil {
		t.Fatal(err)
	}
	fresh := &capacityAPI{http: client, origin: f.origin, token: token, key: pair.phoneKey}
	var account store.AccountIdentity
	if err := fresh.call(ctx, "GET", "/v1/me", nil, &account, 200); err != nil || account.UserID != pair.user {
		t.Fatal("fresh fixture identity could not authenticate", err)
	}
	var current struct {
		State string `json:"state"`
	}
	if err := fresh.call(ctx, "GET", "/v1/devices/current", nil, &current, 200); err != nil || current.State != "revoked" {
		t.Fatal("fresh login revived old device", current.State, err)
	}
	if err := fresh.call(ctx, "POST", "/v1/realtime/tickets", map[string]any{"runtime_id": pair.runtime, "scope": store.GrantScope{Actions: []string{"session.read"}, Workspaces: []string{pair.workspace}, Sessions: []string{pair.session}}}, nil, 403); err != nil {
		t.Fatal("restored grants regained authority", err)
	}
	process.stop(t)
	// Also fence genuinely running deployments, rather than relying only on
	// the cold-start guard. All children here belong to this bounded fixture.
	if _, err := (&store.Postgres{DB: f.db}).QuarantineRecovery(f.ctx, capacityID(), store.OriginalDatabaseEpoch, capacityID()); err != nil {
		t.Fatal(err)
	}
	for _, node := range f.nodes {
		select {
		case err := <-node.process.done:
			node.process.stopped = true
			_ = node.process.log.Close()
			if err == nil {
				t.Fatal("quarantined relay exited successfully")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("running relay ignored recovery fence")
		}
	}
	f.closed(sourcePhone)
	f.closed(sourceHost)
}
