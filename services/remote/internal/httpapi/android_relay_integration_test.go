package httpapi_test

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/approval"
	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/httpapi"
	"dsh-mobile-ustc/services/remote/internal/relay"
	"dsh-mobile-ustc/services/remote/internal/store"
	"dsh-mobile-ustc/services/remote/internal/testsupport"
	jose "github.com/go-jose/go-jose/v4"
)

func TestAndroidAppAgainstPostgresRelayAndNativeDSH(t *testing.T) {
	serial := os.Getenv("REMOTE_TEST_ANDROID_SERIAL")
	if serial == "" {
		t.Skip("run the explicit owned-AVD Android composition")
	}
	cluster := os.Getenv("REMOTE_TEST_CLUSTER_ROOT")
	if cluster == "" {
		t.Fatal("Android composition requires the private cluster")
	}
	_, db := testsupport.PostgresDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	postgres := &store.Postgres{DB: db}
	const (
		orgID          = "11111111-1111-4111-8111-111111111111"
		userID         = "22222222-2222-4222-8222-222222222222"
		hostID         = "33333333-3333-4333-8333-333333333333"
		installationID = "44444444-4444-4444-8444-444444444444"
		runtimeID      = "55555555-5555-4555-8555-555555555555"
		workspaceID    = "77777777-7777-4777-8777-777777777777"
	)
	installationKey, signingKey, authorityKey := approvalKey(t), approvalKey(t), approvalKey(t)
	installationJWK, installationJKT := approvalPublic(t, installationKey)
	oidc := &androidOIDCFixture{t: t, secret: androidSecret(t), key: signingKey, codes: map[string]androidAuthorization{}, proofs: map[string]bool{}}
	var handler *httpapi.Handler
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if !oidc.serve(response, request) {
			handler.ServeHTTP(response, request)
		}
	}))
	t.Cleanup(server.Close)
	oidc.origin, oidc.issuer = server.URL, server.URL+"/issuer"
	statements := []struct {
		query string
		args  []any
	}{
		{`insert into orgs(id,slug,name) values($1,'android-relay','Android relay fixture')`, []any{orgID}},
		{`insert into users(id,issuer,subject) values($1,$2,'android-fixture')`, []any{userID, oidc.issuer}},
		{`insert into org_memberships(org_id,user_id,role) values($1,$2,'member')`, []any{orgID, userID}},
		{`insert into hosts(id,org_id,alias,state) values($1,$2,'Android fixture host','active')`, []any{hostID, orgID}},
		{`insert into installations(id,host_id,owner_user_id,public_jwk,public_key_thumbprint) values($1,$2,$3,$4::jsonb,$5)`, []any{installationID, hostID, userID, string(installationJWK), installationJKT}},
		{`insert into runtimes(id,installation_id,profile_ref,protocol_version) values($1,$2,'android-fixture',1)`, []any{runtimeID, installationID}},
		{`insert into workspaces(id,runtime_id,workspace_ref) values($1,$2,'android-fixture-workspace')`, []any{workspaceID, runtimeID}},
		{`insert into runtime_grants(runtime_id,user_id,role,scope,granted_by) values($1,$2,'owner',$3::jsonb,$2)`, []any{runtimeID, userID,
			`{"actions":["host.list","session.list","session.read","message.submit","session.archive","command.status","approval.decide","grant.manage"],"workspaces":["` + workspaceID + `"],"sessions":[]}`}},
	}
	for _, statement := range statements {
		if _, err := db.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	identity, err := auth.New(auth.Config{Issuer: oidc.issuer, Audience: "urn:dsh-android-relay", JWKSURL: server.URL + "/jwks", AllowedClients: []string{"mobile"},
		RequiredScopes: []string{"remote.access"}, PublicOrigin: server.URL, MaxTokenLifetime: 15 * time.Minute, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	assurance, err := auth.NewAssuranceVerifier([]auth.AssuranceMapping{{Issuer: oidc.issuer, ClientID: "mobile", Profile: "fixture/android-step-up", ACR: "fixture:2", RequiredAMR: []string{"otp"}}})
	if err != nil {
		t.Fatal(err)
	}
	control, err := store.NewApprovalControl(postgres, store.ApprovalPolicy{Version: 7, AssuranceProfile: "fixture/android-step-up", MaxAuthAgeSeconds: 600}, assurance)
	if err != nil {
		t.Fatal(err)
	}
	validFrom, validUntil := time.Now().UTC().Add(-time.Hour).Truncate(time.Millisecond), time.Now().UTC().Add(time.Hour).Truncate(time.Millisecond)
	authority, err := approval.NewAuthorizationSigner(server.URL, "dsh-approval-authority/android-fixture", authorityKey, validFrom, validUntil)
	if err != nil {
		t.Fatal(err)
	}
	leases, err := store.NewApprovalLeaseProvider(control, authority)
	if err != nil {
		t.Fatal(err)
	}
	handler = httpapi.New(postgres, identity, httpapi.Config{Approvals: &relay.ApprovalConfig{Control: control, Leases: leases}})
	challenge, err := postgres.CreateHostCredentialChallenge(ctx, store.UserIdentity{Issuer: oidc.issuer, Subject: "android-fixture"}, installationJKT)
	if err != nil {
		t.Fatal(err)
	}
	hostProof := approvalSign(t, installationKey, jose.ES256, "", "dsh-host-credential-proof+jwt", map[string]any{"iss": installationID, "aud": challenge.Audience,
		"challenge_id": challenge.ChallengeID, "nonce": challenge.Challenge, "iat": time.Now().Unix(), "jti": "android-host-credential-proof-0001"}, nil)
	credential, err := postgres.ExchangeHostCredential(ctx, store.UserIdentity{Issuer: oidc.issuer, Subject: "android-fixture"}, installationJKT, challenge.ChallengeID, hostProof)
	if err != nil {
		t.Fatal(err)
	}
	hostPrivate, err := json.Marshal(jose.JSONWebKey{Key: installationKey})
	if err != nil {
		t.Fatal(err)
	}
	authorityPublic, authorityJKT := approvalPublic(t, authorityKey)
	directory, err := os.MkdirTemp(cluster, "android-relay-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	fixture := map[string]any{
		"deployment": map[string]any{"issuer": oidc.issuer, "client_id": "mobile", "redirect_uri": "cn.edu.ustc.dsh.mobile:/oauth2redirect", "resource": "urn:dsh-android-relay", "audience": "urn:dsh-android-relay",
			"remote_origin": server.URL, "organization_id": orgID, "scopes": []string{"openid", "remote.access"}, "endpoint_origins": []string{server.URL}, "signing_algorithms": []string{"ES256"}},
		"runtime_id": runtimeID, "workspace_id": workspaceID, "approval_host_id": hostID, "host_installation_id": installationID, "host_private_jwk": json.RawMessage(hostPrivate),
		"host_credential": credential.Credential, "android_serial": serial, "android_secret": oidc.secret,
		"approval_policy": map[string]any{"profile": "fixture/android-step-up", "max_auth_age_seconds": 600},
		"ca_pem":          string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})),
		"approval_authority": map[string]any{"issuer": server.URL, "key_id": "dsh-approval-authority/android-fixture", "public_jwk": json.RawMessage(authorityPublic), "key_jkt": authorityJKT, "active": true,
			"valid_from": validFrom.Format("2006-01-02T15:04:05.000Z"), "valid_until": validUntil.Format("2006-01-02T15:04:05.000Z")},
	}
	path := filepath.Join(directory, "host-fixture.json")
	raw, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	repo, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, "node", filepath.Join(repo, "tools/integration/android-dsh-device.mjs"), path)
	command.Dir = repo
	command.Cancel = func() error { return command.Process.Signal(os.Interrupt) }
	command.WaitDelay = 10 * time.Second
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("actual Android/Go/DSH composition failed: %v\n%s", err, output)
	}
	t.Log(string(output))
	resultBytes, err := os.ReadFile(filepath.Join(directory, "android-result.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		State           string   `json:"state"`
		DeviceID        string   `json:"device_id"`
		ProofJKT        string   `json:"proof_key_jkt"`
		ApprovalJKT     string   `json:"approval_key_jkt"`
		Reopened        bool     `json:"reopened"`
		ArchiveRequests []string `json:"archive_requests"`
		SessionID       string   `json:"session_id"`
	}
	if json.Unmarshal(resultBytes, &result) != nil || result.State != "passed" || !result.Reopened {
		t.Fatal("missing native composition result")
	}
	var count int
	var proofJKT, approvalJKT string
	if err := db.QueryRowContext(ctx, `select proof_key_thumbprint,approval_key_thumbprint from devices where id=$1 and user_id=$2`, result.DeviceID, userID).Scan(&proofJKT, &approvalJKT); err != nil {
		t.Fatal(err)
	}
	if proofJKT != result.ProofJKT || approvalJKT != result.ApprovalJKT || proofJKT == approvalJKT {
		t.Fatal("native key registration mismatch")
	}
	if err := db.QueryRowContext(ctx, `select count(*) from devices where user_id=$1`, userID).Scan(&count); err != nil || count != 1 {
		t.Fatal("native device was not enrolled exactly once")
	}
	if err := db.QueryRowContext(ctx, `select count(*) from approvals where runtime_id=$1 and decided_device_id=$2 and ((decision='allow_once' and host_state='settled' and execution_outcome='succeeded') or (decision='reject' and host_state='denied'))`, runtimeID, result.DeviceID).Scan(&count); err != nil || count != 2 {
		t.Fatal("native approval decisions/results are incomplete")
	}
	if len(result.ArchiveRequests) != 2 || result.ArchiveRequests[0] == result.ArchiveRequests[1] {
		t.Fatal("missing independent native archive/restore originals")
	}
	for _, id := range result.ArchiveRequests {
		if err := db.QueryRowContext(ctx, `select count(*) from commands where device_id=$1 and request_id=$2 and runtime_id=$3 and session_id=$4 and state='settled'`, result.DeviceID, id, runtimeID, result.SessionID).Scan(&count); err != nil || count != 1 {
			t.Fatal("native archive/restore receipt is incomplete")
		}
	}
	oidc.mu.Lock()
	exchanges := oidc.exchanges
	oidc.mu.Unlock()
	if exchanges != 1 {
		t.Fatal("native restart unexpectedly repeated the authorization-code exchange")
	}
}
