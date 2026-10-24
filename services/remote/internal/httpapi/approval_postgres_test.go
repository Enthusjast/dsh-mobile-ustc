package httpapi_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/approval"
	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/canonical"
	"dsh-mobile-ustc/services/remote/internal/httpapi"
	"dsh-mobile-ustc/services/remote/internal/relay"
	"dsh-mobile-ustc/services/remote/internal/store"
	"dsh-mobile-ustc/services/remote/internal/testsupport"
	"github.com/coder/websocket"
	jose "github.com/go-jose/go-jose/v4"
)

type approvalWire struct {
	Type          string          `json:"type"`
	RequestID     string          `json:"request_id"`
	PayloadSHA256 string          `json:"payload_sha256"`
	Payload       json.RawMessage `json:"payload"`
}

func approvalKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
func approvalPublic(t *testing.T, key *ecdsa.PrivateKey) ([]byte, string) {
	t.Helper()
	raw, err := json.Marshal(jose.JSONWebKey{Key: &key.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	jkt, err := auth.PublicP256JWKThumbprintJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	return raw, jkt
}
func approvalSign(t *testing.T, key any, algorithm jose.SignatureAlgorithm, keyID, typ string, claims any, extra map[jose.HeaderKey]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	payload, err = canonical.Object(payload)
	if err != nil {
		t.Fatal(err)
	}
	options := (&jose.SignerOptions{}).WithType(jose.ContentType(typ))
	for name, value := range extra {
		options.WithHeader(name, value)
	}
	var signing any = key
	if keyID != "" {
		signing = jose.JSONWebKey{Key: key, KeyID: keyID}
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: algorithm, Key: signing}, options)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}
func approvalRead(t *testing.T, ctx context.Context, connection *websocket.Conn) approvalWire {
	t.Helper()
	readCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	_, raw, err := connection.Read(readCtx)
	if err != nil {
		t.Fatal(err)
	}
	var frame approvalWire
	if json.Unmarshal(raw, &frame) != nil {
		t.Fatal("invalid protocol frame")
	}
	return frame
}
func approvalWrite(t *testing.T, ctx context.Context, connection *websocket.Conn, frame any) {
	t.Helper()
	raw, err := json.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.Write(ctx, websocket.MessageText, raw); err != nil {
		t.Fatal(err)
	}
}

type approvalHTTPClient struct {
	t           *testing.T
	ctx         context.Context
	base, nonce string
	key         *ecdsa.PrivateKey
	jwk         json.RawMessage
}

func (client *approvalHTTPClient) post(token, path string, body any) (int, map[string]any) {
	client.t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		client.t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		ath := sha256.Sum256([]byte(token))
		random := make([]byte, 24)
		_, _ = rand.Read(random)
		claims := map[string]any{"htm": "POST", "htu": "https://remote.example.edu" + path, "iat": time.Now().Unix(), "ath": base64.RawURLEncoding.EncodeToString(ath[:]), "jti": base64.RawURLEncoding.EncodeToString(random), "nonce": client.nonce}
		proof := approvalSign(client.t, client.key, jose.ES256, "", "dpop+jwt", claims, map[jose.HeaderKey]any{"jwk": client.jwk})
		request, err := http.NewRequestWithContext(client.ctx, http.MethodPost, client.base+path, bytes.NewReader(raw))
		if err != nil {
			client.t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "DPoP "+token)
		request.Header.Set("DPoP", proof)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			client.t.Fatal(err)
		}
		data, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil {
			client.t.Fatal(err)
		}
		if nonce := response.Header.Get("DPoP-Nonce"); nonce != "" {
			client.nonce = nonce
		}
		var result map[string]any
		if json.Unmarshal(data, &result) != nil {
			client.t.Fatal("invalid HTTP envelope")
		}
		if response.StatusCode == http.StatusUnauthorized && attempt == 0 {
			continue
		}
		return response.StatusCode, result
	}
	client.t.Fatal("DPoP challenge retry failed")
	return 0, nil
}

// This uses authenticated fixture peers, not the normal DSH plugin. It proves
// the production Go handlers/controller/SQL/signers compose; native DSH guard
// and real npm CLI coverage run separately in the same integration runner.
func TestPostgresSignedApprovalHTTPAndWSSComposeWithCurrentAuthority(t *testing.T) {
	ctx, database := testsupport.PostgresDatabase(t)
	postgres := &store.Postgres{DB: database}
	const hostID = "11111111-1111-4111-8111-111111111111"
	const installID = "22222222-2222-4222-8222-222222222222"
	const runtimeID = "33333333-3333-4333-8333-333333333333"
	const epoch = "44444444-4444-4444-8444-444444444444"
	const approvalID = "66666666-6666-4666-8666-666666666666"
	const executionID = "77777777-7777-4777-8777-777777777777"
	const workspaceID = "88888888-8888-4888-8888-888888888888"
	const userID = "99999999-9999-4999-8999-999999999999"
	const deviceID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	const orgID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	hostKey, phoneProof, phoneApproval, serviceKey := approvalKey(t), approvalKey(t), approvalKey(t), approvalKey(t)
	hostJWK, hostJKT := approvalPublic(t, hostKey)
	proofJWK, proofJKT := approvalPublic(t, phoneProof)
	phoneJWK, phoneJKT := approvalPublic(t, phoneApproval)
	sessionID, err := store.MobileSessionID(runtimeID, "native-approval-transport")
	if err != nil {
		t.Fatal(err)
	}
	credential := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	credentialHash := sha256.Sum256([]byte(credential))
	statements := []struct {
		query string
		args  []any
	}{
		{`insert into orgs(id,slug,name) values($1,'approval-wire','Approval fixture')`, []any{orgID}},
		{`insert into users(id,issuer,subject) values($1,'https://id.example.edu','owner')`, []any{userID}},
		{`insert into org_memberships(org_id,user_id,role) values($1,$2,'member')`, []any{orgID, userID}},
		{`insert into devices(id,user_id,name,approval_public_jwk,approval_key_thumbprint,proof_public_jwk,proof_key_thumbprint) values($1,$2,'fixture phone',$3,$4,$5,$6)`, []any{deviceID, userID, phoneJWK, phoneJKT, proofJWK, proofJKT}},
		{`insert into hosts(id,org_id,alias,state) values($1,$2,'fixture host','active')`, []any{hostID, orgID}},
		{`insert into installations(id,host_id,owner_user_id,public_jwk,public_key_thumbprint) values($1,$2,$3,$4,$5)`, []any{installID, hostID, userID, hostJWK, hostJKT}},
		{`insert into runtimes(id,installation_id,profile_ref) values($1,$2,'approval-profile')`, []any{runtimeID, installID}},
		{`insert into workspaces(id,runtime_id,workspace_ref) values($1,$2,'fixture-workspace')`, []any{workspaceID, runtimeID}},
		{`insert into runtime_grants(runtime_id,user_id,role,scope,granted_by) values($1,$2,'owner',$3,$2)`, []any{runtimeID, userID, `{"actions":["grant.manage","approval.decide","session.read"],"workspaces":["` + workspaceID + `"],"sessions":[]}`}},
		{`insert into host_connection_credentials(token_sha256,installation_id,key_version,expires_at) values($1,$2,1,clock_timestamp()+interval '5 minutes')`, []any{credentialHash[:], installID}},
	}
	for _, statement := range statements {
		if _, err := database.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	issuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(response).Encode(map[string]any{"keys": []any{jose.JSONWebKey{Key: &issuerKey.PublicKey, KeyID: "idp-key", Algorithm: "RS256", Use: "sig"}}})
	}))
	defer jwks.Close()
	identity, err := auth.New(auth.Config{Issuer: "https://id.example.edu", Audience: "urn:dsh-remote", JWKSURL: jwks.URL, AllowedClients: []string{"android"}, RequiredScopes: []string{"remote.access"}, PublicOrigin: "https://remote.example.edu", MaxTokenLifetime: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	assurance, err := auth.NewAssuranceVerifier([]auth.AssuranceMapping{{Issuer: "https://id.example.edu", ClientID: "android", Profile: "school/step-up", ACR: "school:2", RequiredAMR: []string{"otp"}}})
	if err != nil {
		t.Fatal(err)
	}
	control, err := store.NewApprovalControl(postgres, store.ApprovalPolicy{Version: 7, AssuranceProfile: "school/step-up", MaxAuthAgeSeconds: 60}, assurance)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	signer, err := approval.NewAuthorizationSigner("https://remote.example.edu", "dsh-approval-authority/wire-test", serviceKey, now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	provider, err := store.NewApprovalLeaseProvider(control, signer)
	if err != nil {
		t.Fatal(err)
	}
	handler := httpapi.New(postgres, identity, httpapi.Config{Approvals: &relay.ApprovalConfig{Control: control, Leases: provider}})
	server := httptest.NewServer(handler)
	defer server.Close()
	claims := map[string]any{"iss": "https://id.example.edu", "sub": "owner", "aud": "urn:dsh-remote", "client_id": "android", "jti": "approval-token", "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "scope": "remote.access", "cnf": map[string]any{"jkt": proofJKT}, "auth_time": now.Add(-2 * time.Second).Unix(), "acr": "school:2", "amr": []string{"otp"}}
	access := approvalSign(t, issuerKey, jose.RS256, "idp-key", "at+jwt", claims, nil)
	caller := &approvalHTTPClient{t: t, ctx: ctx, base: server.URL, key: phoneProof, jwk: proofJWK}
	caps := []string{"approval.signed.v1", "command.relay.v1", "connection.heartbeat.v1", "session.catalog.v1", "session.read.v1"}
	slices.Sort(caps)
	connect := func(role, token string, key *ecdsa.PrivateKey) (*websocket.Conn, string) {
		t.Helper()
		connection, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+"/v1/realtime", &websocket.DialOptions{Subprotocols: []string{"dsh.remote.v1"}, HTTPHeader: http.Header{"Authorization": []string{token}}})
		if err != nil {
			t.Fatal(err)
		}
		challenge := approvalRead(t, ctx, connection)
		var value map[string]any
		_ = json.Unmarshal(challenge.Payload, &value)
		connectionID := value["connection_id"].(string)
		hello := map[string]any{"capabilities": caps}
		subject := deviceID
		digest := auth.RelayHelloDigest("device", deviceID, "1", strings.Join(caps, "\n"))
		if role == "host" {
			subject = installID
			digest = auth.RelayHelloDigest("host", runtimeID, epoch, "0.2.1-rc.2", "fixture", "fixture", "1", strings.Join(caps, "\n"))
			hello["runtime_id"], hello["runtime_epoch"], hello["dsh_version"], hello["application_version"], hello["plugin_version"], hello["protocol_version"] = runtimeID, epoch, "0.2.1-rc.2", "fixture", "fixture", 1
		} else {
			hello["device_id"], hello["protocols"] = deviceID, []int{1}
		}
		proofClaims := map[string]any{"iss": subject, "aud": auth.RelayHandshakeAudience, "challenge_id": value["challenge_id"], "connection_id": connectionID, "nonce": value["nonce"], "runtime_id": runtimeID, "hello_sha256": digest, "iat": time.Now().Unix(), "jti": "handshake-" + connectionID}
		if role == "host" {
			proofClaims["runtime_epoch"] = epoch
		}
		hello["proof"] = approvalSign(t, key, jose.ES256, "", "dsh-relay-handshake-proof+jwt", proofClaims, nil)
		approvalWrite(t, ctx, connection, map[string]any{"v": 1, "type": "hello.proof", "payload": hello})
		if ack := approvalRead(t, ctx, connection); ack.Type != "hello.ok" {
			t.Fatalf("handshake failed: %+v", ack)
		}
		return connection, connectionID
	}
	host, hostConnection := connect("host", "DSH-Host "+credential, hostKey)
	defer host.CloseNow()
	approvalWrite(t, ctx, host, map[string]any{"v": 1, "type": "session.catalog", "request_id": approvalID, "runtime_id": runtimeID, "runtime_epoch": epoch, "payload": map[string]any{"mode": "snapshot", "index": 0, "complete": true, "items": []any{map[string]any{"session_id": sessionID, "dsh_session_id": "native-approval-transport", "workspace_id": workspaceID, "state": "running", "last_persisted_seq": -1}}}})
	if ack := approvalRead(t, ctx, host); ack.Type != "session.catalog.ack" {
		t.Fatalf("catalog failed: %+v", ack)
	}
	code, ticket := caller.post(access, "/v1/realtime/tickets", map[string]any{"runtime_id": runtimeID, "scope": map[string]any{"actions": []string{"approval.decide", "session.read"}, "workspaces": []string{workspaceID}, "sessions": []string{}}})
	if code != http.StatusCreated {
		t.Fatalf("ticket failed: %d %+v", code, ticket)
	}
	device, deviceConnection := connect("device", "DSH-Ticket "+ticket["data"].(map[string]any)["ticket"].(string), phoneProof)
	defer device.CloseNow()
	approvalWrite(t, ctx, device, map[string]any{"v": 1, "type": "approval.subscribe", "request_id": approvalID, "runtime_id": runtimeID, "payload": map[string]any{}})
	if snapshot := approvalRead(t, ctx, device); snapshot.Type != "approval.snapshot" {
		t.Fatalf("snapshot failed: %+v", snapshot)
	}
	age := int64(60)
	request := approval.Context{Domain: approval.ContextDomain, ProtocolVersion: 1, Identity: approval.Identity{HostID: hostID, InstallationID: installID, RuntimeID: runtimeID, RuntimeEpoch: epoch, SessionID: sessionID, ApprovalID: approvalID, ExecutionID: executionID},
		DSHSessionID: "native-approval-transport", CallID: "private-native-approval-call", Tool: "bash", Arguments: json.RawMessage(`{"command":"private-approval-argument"}`), Workspace: approval.Workspace{WorkspaceID: workspaceID, RootSHA256: strings.Repeat("a", 64)}, Resources: []approval.Resource{}, Nonce: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)), PolicyVersion: 7, RequiredAssurance: approval.Assurance{Profile: "school/step-up", MaxAuthAgeSeconds: &age}, CreatedAt: time.Now().Add(-time.Second).UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z"), ExpiresAt: time.Now().Add(2 * time.Minute).UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")}
	raw, _ := json.Marshal(request)
	binding, err := approval.ContextBinding(raw)
	if err != nil {
		t.Fatal(err)
	}
	frame := func(kind, id string, payload any) map[string]any {
		return map[string]any{"v": 1, "type": kind, "request_id": id, "runtime_id": runtimeID, "runtime_epoch": epoch, "session_id": sessionID, "payload": payload}
	}
	approvalWrite(t, ctx, host, frame("approval.request", approvalID, map[string]any{"context": request}))
	if ack := approvalRead(t, ctx, host); ack.Type != "approval.registered" {
		t.Fatalf("request failed: %+v", ack)
	}
	if reference := approvalRead(t, ctx, device); reference.Type != "approval.reference" {
		t.Fatalf("missing pending reference: %+v", reference)
	}
	decision := approval.Decision{Domain: approval.DecisionDomain, ProtocolVersion: 1, Identity: request.Identity, BindingSHA256: binding.SHA256, Decision: "allow_once", UserID: userID, DeviceID: deviceID, KeyVersion: 1, PolicyVersion: 7, Nonce: request.Nonce, IssuedAt: time.Now().UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z"), ExpiresAt: request.ExpiresAt}
	compact := approvalSign(t, phoneApproval, jose.ES256, approval.KeyID(deviceID, 1), approval.JWSType, decision, nil)
	postDecision := func(token, proof string) (int, map[string]any) {
		t.Helper()
		type response struct {
			code int
			body map[string]any
		}
		done := make(chan response, 1)
		go func() {
			code, body := caller.post(token, "/v1/approvals/"+approvalID+"/decisions", map[string]any{"connection_id": deviceConnection, "decision_jws": proof})
			done <- response{code, body}
		}()
		lookup := approvalRead(t, ctx, host)
		if lookup.Type != "approval.details.get" {
			t.Fatalf("missing live details lookup: %+v", lookup)
		}
		approvalWrite(t, ctx, host, frame("approval.details", lookup.RequestID, map[string]any{"context": request}))
		select {
		case result := <-done:
			return result.code, result.body
		case <-ctx.Done():
			t.Fatal("decision request did not settle")
			return 0, nil
		}
	}
	claims["acr"] = "school:weak"
	claims["jti"] = "weak-token"
	weak := approvalSign(t, issuerKey, jose.RS256, "idp-key", "at+jwt", claims, nil)
	if code, body := postDecision(weak, compact); code != http.StatusForbidden || body["error"].(map[string]any)["code"] != "approval.assurance_required" {
		t.Fatalf("weak authentication approved: %d %+v", code, body)
	}
	parts := strings.Split(compact, ".")
	if parts[2][0] == 'A' {
		parts[2] = "B" + parts[2][1:]
	} else {
		parts[2] = "A" + parts[2][1:]
	}
	if code, body := postDecision(access, strings.Join(parts, ".")); code != http.StatusBadRequest || body["error"].(map[string]any)["code"] != "approval.decision_invalid" {
		t.Fatalf("altered signature accepted: %d %+v", code, body)
	}
	var pending int
	if err := database.QueryRowContext(ctx, `select count(*) from approvals where id=$1 and state='pending' and decision_jws is null`, approvalID).Scan(&pending); err != nil || pending != 1 {
		t.Fatal("invalid decisions consumed pending approval")
	}
	code, result := postDecision(access, compact)
	if code != http.StatusOK || result["data"].(map[string]any)["delivery"] != "forwarded" {
		t.Fatalf("valid decision was not forwarded: %d %+v", code, result)
	}
	forward := approvalRead(t, ctx, host)
	var proof struct {
		Decision      string `json:"decision_jws"`
		Authorization string `json:"authorization_jws"`
	}
	_ = json.Unmarshal(forward.Payload, &proof)
	verified, err := approval.VerifyAuthorization(proof.Authorization, signer.Authority(), raw, proof.Decision, hostConnection, time.Now())
	if err != nil || forward.Type != "approval.decision" {
		t.Fatalf("real lease failed independent validation: %v %+v", err, forward)
	}
	if reference := approvalRead(t, ctx, device); reference.Type != "approval.reference" {
		t.Fatal("accepted reference missing")
	}
	for _, state := range []string{"consumed", "settled"} {
		payload := map[string]any{"approval_id": approvalID, "execution_id": executionID, "binding_sha256": binding.SHA256, "decision_payload_sha256": verified.Decision.PayloadSHA256, "state": state}
		if state == "settled" {
			payload["execution_outcome"] = "failed"
		}
		facts := map[string]any{"type": "approval.result", "runtime_id": runtimeID, "runtime_epoch": epoch, "session_id": sessionID, "payload": payload}
		encoded, _ := json.Marshal(facts)
		encoded, err = canonical.Object(encoded)
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(encoded)
		report := frame("approval.result", executionID, payload)
		report["payload_sha256"] = hex.EncodeToString(hash[:])
		approvalWrite(t, ctx, host, report)
		if ack := approvalRead(t, ctx, host); ack.Type != "approval.result.ack" || ack.PayloadSHA256 != hex.EncodeToString(hash[:]) {
			t.Fatalf("result acknowledgement lost binding: %+v", ack)
		}
		if update := approvalRead(t, ctx, device); update.Type != "approval.reference" {
			t.Fatal("native result reference missing")
		}
	}
	_ = host.CloseNow()
	deadline := time.Now().Add(time.Second)
	for {
		var offline bool
		if err := database.QueryRowContext(ctx, `select connection_id is null from runtimes where id=$1`, runtimeID).Scan(&offline); err != nil {
			t.Fatal(err)
		}
		if offline {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("host did not detach")
		}
		time.Sleep(5 * time.Millisecond)
	}
	approvalWrite(t, ctx, device, map[string]any{"v": 1, "type": "approval.status.get", "request_id": executionID, "runtime_id": runtimeID, "payload": map[string]string{"approval_id": approvalID}})
	metadata := approvalRead(t, ctx, device)
	var final struct {
		Status store.ApprovalStatus `json:"status"`
	}
	_ = json.Unmarshal(metadata.Payload, &final)
	if metadata.Type != "approval.reference" || final.Status.HostState != "settled" || final.Status.Outcome != "failed" {
		t.Fatalf("offline reconciliation lost known result: %+v %+v", metadata, final)
	}
	if _, err := database.ExecContext(ctx, `update runtime_grants set grant_version=2 where runtime_id=$1 and user_id=$2`, runtimeID, userID); err != nil {
		t.Fatal(err)
	}
	approvalWrite(t, ctx, device, map[string]any{"v": 1, "type": "approval.status.get", "request_id": executionID, "runtime_id": runtimeID, "payload": map[string]string{"approval_id": approvalID}})
	if denied := approvalRead(t, ctx, device); denied.Type != "error" || !bytes.Contains(denied.Payload, []byte("access.denied")) {
		t.Fatalf("old socket survived changed grant: %+v", denied)
	}
	var stored string
	if err := database.QueryRowContext(ctx, `select row_to_json(a)::text from approvals a where id=$1`, approvalID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private-approval-argument", "private-native-approval-call", "arguments", "resources"} {
		if strings.Contains(stored, secret) {
			t.Fatalf("service persisted full context field %s", secret)
		}
	}
	if err := handler.Drain(ctx); err != nil {
		t.Fatal(fmt.Errorf("drain approval transport: %w", err))
	}
}
