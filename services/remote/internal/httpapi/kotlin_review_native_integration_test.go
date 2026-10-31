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
	remotecontrol "dsh-mobile-ustc/services/remote/internal/control"
	"dsh-mobile-ustc/services/remote/internal/httpapi"
	"dsh-mobile-ustc/services/remote/internal/relay"
	"dsh-mobile-ustc/services/remote/internal/store"
	"dsh-mobile-ustc/services/remote/internal/testsupport"
	jose "github.com/go-jose/go-jose/v4"
)

func TestKotlinReviewConsumersAgainstNativeHostOverTLS(t *testing.T) {
	classpath := os.Getenv("REMOTE_TEST_KOTLIN_CLASSPATH")
	if classpath == "" {
		t.Skip("run npm run test:remote-kotlin for the actual Kotlin client composition")
	}
	cluster := os.Getenv("REMOTE_TEST_CLUSTER_ROOT")
	if cluster == "" {
		t.Fatal("Kotlin composition requires the private test cluster")
	}
	_, db := testsupport.PostgresDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	postgres := &store.Postgres{DB: db}
	const (
		issuer         = "https://id.fixture.invalid"
		orgID          = "11111111-1111-4111-8111-111111111111"
		userID         = "22222222-2222-4222-8222-222222222222"
		hostID         = "33333333-3333-4333-8333-333333333333"
		installationID = "44444444-4444-4444-8444-444444444444"
		runtimeID      = "55555555-5555-4555-8555-555555555555"
		sessionID      = "66666666-6666-4666-8666-666666666666"
		workspaceID    = "77777777-7777-4777-8777-777777777777"
	)
	proof := approvalKey(t)
	proofJWK, proofJKT := approvalPublic(t, proof)
	phoneApprovalKey := approvalKey(t)
	approvalJWK, approvalJKT := approvalPublic(t, phoneApprovalKey)
	installationKey := approvalKey(t)
	installationJWK, installationJKT := approvalPublic(t, installationKey)
	statements := []struct {
		query string
		args  []any
	}{
		{`insert into orgs(id,slug,name) values($1,'kotlin-relay','Kotlin relay fixture')`, []any{orgID}},
		{`insert into users(id,issuer,subject) values($1,$2,'kotlin-fixture')`, []any{userID, issuer}},
		{`insert into org_memberships(org_id,user_id,role) values($1,$2,'member')`, []any{orgID, userID}},
		{`insert into hosts(id,org_id,alias,state) values($1,$2,'Kotlin fixture host','active')`, []any{hostID, orgID}},
		{`insert into installations(id,host_id,owner_user_id,public_jwk,public_key_thumbprint) values($1,$2,$3,$4::jsonb,$5)`, []any{installationID, hostID, userID, string(installationJWK), installationJKT}},
		{`insert into runtimes(id,installation_id,profile_ref,protocol_version) values($1,$2,'kotlin-fixture',1)`, []any{runtimeID, installationID}},
		{`insert into workspaces(id,runtime_id,workspace_ref) values($1,$2,'opaque-fixture-workspace')`, []any{workspaceID, runtimeID}},
		{`insert into sessions(id,runtime_id,workspace_id,dsh_session_id) values($1,$2,$3,'opaque-fixture-native')`, []any{sessionID, runtimeID, workspaceID}},
		{`insert into runtime_grants(runtime_id,user_id,role,scope,granted_by) values($1,$2,'owner',$3::jsonb,$2)`, []any{runtimeID, userID, `{"actions":["host.list","session.list","workspace.list","session.read","session.changes.read","session.fork","session.create","command.status"],"workspaces":["` + workspaceID + `"],"sessions":["` + sessionID + `"]}`}},
	}
	for _, statement := range statements {
		if _, err := db.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	deviceID, err := postgres.RegisterDevice(ctx, store.DeviceRegistration{Issuer: issuer, Subject: "kotlin-fixture", Name: "Kotlin fixture phone",
		ApprovalPublicJWK: approvalJWK, ApprovalKeyThumbprint: approvalJKT, ProofPublicJWK: proofJWK, ProofKeyThumbprint: proofJKT})
	if err != nil {
		t.Fatal(err)
	}
	signing := approvalKey(t)
	public, err := json.Marshal(jose.JSONWebKey{Key: &signing.PublicKey, KeyID: "kotlin-issuer", Algorithm: "ES256", Use: "sig"})
	if err != nil {
		t.Fatal(err)
	}
	jwks := json.RawMessage(`{"keys":[` + string(public) + `]}`)
	keys := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write(jwks)
	}))
	t.Cleanup(keys.Close)
	var handler *httpapi.Handler
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) { handler.ServeHTTP(response, request) }))
	t.Cleanup(server.Close)
	identity, err := auth.New(auth.Config{Issuer: issuer, Audience: "urn:dsh-kotlin-relay", JWKSURL: keys.URL, AllowedClients: []string{"mobile", "fixture-host"}, RequiredScopes: []string{"remote.access"}, PublicOrigin: server.URL, MaxTokenLifetime: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	assurance, err := auth.NewAssuranceVerifier([]auth.AssuranceMapping{{Issuer: issuer, ClientID: "mobile", Profile: "fixture/step-up", ACR: "fixture:2", RequiredAMR: []string{"otp"}}})
	if err != nil {
		t.Fatal(err)
	}
	control, err := store.NewApprovalControl(postgres, store.ApprovalPolicy{Version: 7, AssuranceProfile: "fixture/step-up", MaxAuthAgeSeconds: 60}, assurance)
	if err != nil {
		t.Fatal(err)
	}
	authorityKey := approvalKey(t)
	validFrom, validUntil := time.Now().UTC().Add(-time.Hour).Truncate(time.Millisecond), time.Now().UTC().Add(time.Hour).Truncate(time.Millisecond)
	authority, err := approval.NewAuthorizationSigner(server.URL, "dsh-approval-authority/kotlin-fixture", authorityKey, validFrom, validUntil)
	if err != nil {
		t.Fatal(err)
	}
	leases, err := store.NewApprovalLeaseProvider(control, authority)
	if err != nil {
		t.Fatal(err)
	}
	handler = httpapi.New(postgres, identity, httpapi.Config{HostClientIDs: []string{"fixture-host"}, Approvals: &relay.ApprovalConfig{Control: control, Leases: leases}})
	workerContext, stopWorkers := context.WithCancel(ctx)
	workersDone := make(chan struct{})
	go func() { remotecontrol.Run(workerContext, postgres, handler); close(workersDone) }()
	defer func() { stopWorkers(); <-workersDone }()
	now := time.Now().UTC().Truncate(time.Second)
	access := approvalSign(t, signing, jose.ES256, "kotlin-issuer", "at+jwt", map[string]any{"iss": issuer, "sub": "kotlin-fixture", "aud": "urn:dsh-kotlin-relay", "client_id": "mobile",
		"jti": "kotlin-composition-access-token", "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "scope": "remote.access", "cnf": map[string]any{"jkt": proofJKT}, "auth_time": now.Unix(), "acr": "fixture:2", "amr": []string{"otp"}}, nil)
	private, err := json.Marshal(jose.JSONWebKey{Key: proof})
	if err != nil {
		t.Fatal(err)
	}
	fixture := map[string]any{
		"deployment": map[string]any{"issuer": issuer, "client_id": "mobile", "redirect_uri": "cn.edu.ustc.dsh.mobile:/oauth2redirect", "resource": "urn:dsh-kotlin-relay", "audience": "urn:dsh-kotlin-relay",
			"remote_origin": server.URL, "organization_id": orgID, "scopes": []string{"openid", "remote.access"}, "endpoint_origins": []string{issuer}, "signing_algorithms": []string{"ES256"}},
		"proof_jwk": json.RawMessage(private), "access_token": access, "issuer_jwks": jwks, "device_id": deviceID, "runtime_id": runtimeID, "session_id": sessionID, "workspace_id": workspaceID, "subject": "kotlin-fixture",
		"access_expires_at": now.Add(5 * time.Minute).UnixMilli(), "ca_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})),
	}
	approvalPrivate, err := json.Marshal(jose.JSONWebKey{Key: phoneApprovalKey})
	if err != nil {
		t.Fatal(err)
	}
	authorityPublic, authorityJKT := approvalPublic(t, authorityKey)
	fixture["approval_host_id"] = hostID
	fixture["approval_jwk"] = json.RawMessage(approvalPrivate)
	fixture["registered_approval"] = map[string]any{"user_id": userID, "device_id": deviceID, "key_version": 1, "active": true, "public_jwk": json.RawMessage(approvalJWK), "approval_key_jkt": approvalJKT}
	fixture["approval_authority"] = map[string]any{"issuer": server.URL, "key_id": "dsh-approval-authority/kotlin-fixture", "public_jwk": json.RawMessage(authorityPublic), "key_jkt": authorityJKT, "active": true,
		"valid_from": validFrom.Format("2006-01-02T15:04:05.000Z"), "valid_until": validUntil.Format("2006-01-02T15:04:05.000Z")}
	directory, err := os.MkdirTemp(cluster, "kotlin-relay-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	path := filepath.Join(directory, "fixture.json")
	raw, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	challenge, err := postgres.CreateHostCredentialChallenge(ctx, store.UserIdentity{Issuer: issuer, Subject: "kotlin-fixture"}, installationJKT)
	if err != nil {
		t.Fatal(err)
	}
	hostProof := approvalSign(t, installationKey, jose.ES256, "", "dsh-host-credential-proof+jwt", map[string]any{
		"iss": installationID, "aud": challenge.Audience, "challenge_id": challenge.ChallengeID, "nonce": challenge.Challenge,
		"iat": time.Now().Unix(), "jti": "kotlin-host-credential-proof-0001",
	}, nil)
	credential, err := postgres.ExchangeHostCredential(ctx, store.UserIdentity{Issuer: issuer, Subject: "kotlin-fixture"}, installationJKT, challenge.ChallengeID, hostProof)
	if err != nil {
		t.Fatal(err)
	}
	hostPrivate, err := json.Marshal(jose.JSONWebKey{Key: installationKey})
	if err != nil {
		t.Fatal(err)
	}
	fixture["host_installation_id"] = installationID
	fixture["host_private_jwk"] = json.RawMessage(hostPrivate)
	fixture["host_credential"] = credential.Credential
	fixture["workspace_id"] = workspaceID
	fixture["revoke_marker"] = filepath.Join(directory, "revoke-ready")
	raw, err = json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	revokeDone := make(chan error, 1)
	go func() {
		for {
			if _, err := os.Stat(filepath.Join(directory, "revoke-ready")); err == nil {
				revokeDone <- postgres.RevokeDevice(ctx, issuer, "kotlin-fixture", deviceID)
				return
			}
			select {
			case <-ctx.Done():
				revokeDone <- ctx.Err()
				return
			case <-time.After(25 * time.Millisecond):
			}
		}
	}()
	repo, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, "node", filepath.Join(repo, "tools", "integration", "kotlin-dsh-review.mjs"), path)
	command.Dir = repo
	command.Cancel = func() error { return command.Process.Signal(os.Interrupt) }
	command.WaitDelay = 6 * time.Second
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("actual Kotlin review/native composition failed: %v\n%s", err, output)
	}
	if err := <-revokeDone; err != nil {
		t.Fatal("authoritative fixture revoke failed", err)
	}
	var grants int
	if err := db.QueryRowContext(ctx, `select count(*) from runtime_grants where runtime_id=$1 and grant_version=1`, runtimeID).Scan(&grants); err != nil || grants != 1 {
		t.Fatal("review fixture changed its original grant")
	}
	t.Log(string(output))
}
