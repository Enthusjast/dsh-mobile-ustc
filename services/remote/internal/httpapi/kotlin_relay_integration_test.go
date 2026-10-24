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

	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/httpapi"
	"dsh-mobile-ustc/services/remote/internal/store"
	"dsh-mobile-ustc/services/remote/internal/testsupport"
	jose "github.com/go-jose/go-jose/v4"
)

func TestKotlinReadClientAgainstPostgresRelayOverTLS(t *testing.T) {
	classpath := os.Getenv("REMOTE_TEST_KOTLIN_CLASSPATH")
	if classpath == "" {
		t.Skip("run npm run test:remote-kotlin for the actual Kotlin client composition")
	}
	cluster := os.Getenv("REMOTE_TEST_CLUSTER_ROOT")
	if cluster == "" {
		t.Fatal("Kotlin composition requires the private test cluster")
	}
	_, db := testsupport.PostgresDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
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
	approvalJWK, approvalJKT := approvalPublic(t, approvalKey(t))
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
		{`insert into runtime_grants(runtime_id,user_id,role,scope,granted_by) values($1,$2,'viewer',$3::jsonb,$2)`, []any{runtimeID, userID, `{"actions":["host.list","session.list","session.read"],"workspaces":["` + workspaceID + `"],"sessions":["` + sessionID + `"]}`}},
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
	identity, err := auth.New(auth.Config{Issuer: issuer, Audience: "urn:dsh-kotlin-relay", JWKSURL: keys.URL, AllowedClients: []string{"mobile"}, RequiredScopes: []string{"remote.access"}, PublicOrigin: server.URL, MaxTokenLifetime: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	handler = httpapi.New(postgres, identity)
	now := time.Now().UTC().Truncate(time.Second)
	access := approvalSign(t, signing, jose.ES256, "kotlin-issuer", "at+jwt", map[string]any{"iss": issuer, "sub": "kotlin-fixture", "aud": "urn:dsh-kotlin-relay", "client_id": "mobile",
		"jti": "kotlin-composition-access-token", "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "scope": "remote.access", "cnf": map[string]any{"jkt": proofJKT}}, nil)
	private, err := json.Marshal(jose.JSONWebKey{Key: proof})
	if err != nil {
		t.Fatal(err)
	}
	fixture := map[string]any{
		"deployment": map[string]any{"issuer": issuer, "client_id": "mobile", "redirect_uri": "cn.edu.ustc.dsh.mobile:/oauth2redirect", "resource": "urn:dsh-kotlin-relay", "audience": "urn:dsh-kotlin-relay",
			"remote_origin": server.URL, "organization_id": orgID, "scopes": []string{"openid", "remote.access"}, "endpoint_origins": []string{issuer}, "signing_algorithms": []string{"ES256"}},
		"proof_jwk": json.RawMessage(private), "access_token": access, "issuer_jwks": jwks, "device_id": deviceID, "runtime_id": runtimeID, "session_id": sessionID, "subject": "kotlin-fixture",
		"access_expires_at": now.Add(5 * time.Minute).UnixMilli(), "ca_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})),
	}
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
	java := os.Getenv("REMOTE_TEST_JAVA")
	if java == "" {
		java = "java"
	}
	command := exec.CommandContext(ctx, java, "-cp", classpath, "cn.edu.ustc.dsh.network.RunRelayProbe", path)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("actual Kotlin Relay client failed: %v\n%s", err, output)
	}
	t.Log(string(output))

	// The same TLS service now carries actual npm DSH history and live content into
	// the production Kotlin reader. Host and model are isolated local fixtures.
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
	raw, err = json.Marshal(fixture)
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
	command = exec.CommandContext(ctx, "node", filepath.Join(repo, "tools", "integration", "kotlin-dsh-reader.mjs"), path)
	command.Dir = repo
	command.Cancel = func() error { return command.Process.Signal(os.Interrupt) }
	command.WaitDelay = 6 * time.Second
	output, err = command.CombinedOutput()
	if err != nil {
		t.Fatalf("actual Kotlin/Go/DSH content chain failed: %v\n%s", err, output)
	}
	t.Log(string(output))
}
