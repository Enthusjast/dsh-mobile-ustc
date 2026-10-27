package httpapi_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/files"
	"dsh-mobile-ustc/services/remote/internal/httpapi"
	"dsh-mobile-ustc/services/remote/internal/store"
	"dsh-mobile-ustc/services/remote/internal/testsupport"
	jose "github.com/go-jose/go-jose/v4"
)

const fileRuntimeID = "66666666-6666-4666-8666-666666666666"
const fileWorkspaceID = "77777777-7777-4777-8777-777777777777"

type fileHTTPCaller struct {
	t           *testing.T
	ctx         context.Context
	client      *http.Client
	base, nonce string
	key         *ecdsa.PrivateKey
	jwk         json.RawMessage
}

func (caller *fileHTTPCaller) call(token, method, path string, body any) (int, json.RawMessage) {
	caller.t.Helper()
	var raw []byte
	if body != nil {
		var err error
		raw, err = json.Marshal(body)
		if err != nil {
			caller.t.Fatal(err)
		}
	}
	for attempt := 0; attempt < 2; attempt++ {
		ath := sha256.Sum256([]byte(token))
		random := make([]byte, 24)
		_, _ = rand.Read(random)
		claims := map[string]any{"htm": method, "htu": caller.base + path, "iat": time.Now().Unix(), "ath": base64.RawURLEncoding.EncodeToString(ath[:]), "jti": base64.RawURLEncoding.EncodeToString(random), "nonce": caller.nonce}
		proof := approvalSign(caller.t, caller.key, jose.ES256, "", "dpop+jwt", claims, map[jose.HeaderKey]any{"jwk": caller.jwk})
		request, err := http.NewRequestWithContext(caller.ctx, method, caller.base+path, bytes.NewReader(raw))
		if err != nil {
			caller.t.Fatal(err)
		}
		request.Header.Set("Authorization", "DPoP "+token)
		request.Header.Set("DPoP", proof)
		if body != nil {
			request.Header.Set("Content-Type", "application/json")
		}
		response, err := caller.client.Do(request)
		if err != nil {
			caller.t.Fatal(err)
		}
		data, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil {
			caller.t.Fatal(err)
		}
		if nonce := response.Header.Get("DPoP-Nonce"); nonce != "" {
			caller.nonce = nonce
		}
		if response.StatusCode == 401 && attempt == 0 && response.Header.Get("DPoP-Nonce") != "" {
			continue
		}
		return response.StatusCode, data
	}
	caller.t.Fatal("file DPoP challenge did not settle")
	return 0, nil
}

type fileHTTPFixture struct {
	exports                                *files.Exports
	ctx                                    context.Context
	database                               *sql.DB
	service                                *files.Service
	peer                                   *fileObjectPeer
	objects                                *httptest.Server
	server                                 *httptest.Server
	caller, second                         *fileHTTPCaller
	token, secondToken, hostToken, session string
	counter                                int
	scannerAddress, jwksURL                string
}

func newFileHTTPFixture(t *testing.T, crossNode ...bool) *fileHTTPFixture {
	t.Helper()
	ctx, database := testsupport.PostgresDatabase(t)
	postgres := &store.Postgres{DB: database}
	proof, approval, secondProof, issuer := approvalKey(t), approvalKey(t), approvalKey(t), approvalKey(t)
	proofJWK, proofJKT := approvalPublic(t, proof)
	approvalJWK, approvalJKT := approvalPublic(t, approval)
	secondJWK, secondJKT := approvalPublic(t, secondProof)
	session, err := store.MobileSessionID(fileRuntimeID, "native-file-session")
	if err != nil {
		t.Fatal(err)
	}
	statements := []struct {
		sql  string
		args []any
	}{
		{`insert into orgs(id,slug,name) values('11111111-1111-4111-8111-111111111111','files','Files fixture')`, nil},
		{`insert into users(id,issuer,subject) values('22222222-2222-4222-8222-222222222222','https://id.example.edu','file-owner')`, nil},
		{`insert into org_memberships(org_id,user_id,role) values('11111111-1111-4111-8111-111111111111','22222222-2222-4222-8222-222222222222','member')`, nil},
		{`insert into devices(id,user_id,name,approval_public_jwk,approval_key_thumbprint,proof_public_jwk,proof_key_thumbprint) values('33333333-3333-4333-8333-333333333333','22222222-2222-4222-8222-222222222222','file phone',$1,$2,$3,$4),('88888888-8888-4888-8888-888888888888','22222222-2222-4222-8222-222222222222','second phone',$1,$5,$6,$7)`, []any{approvalJWK, approvalJKT, proofJWK, proofJKT, "second-approval-key", secondJWK, secondJKT}},
		{`insert into hosts(id,org_id,alias,state) values('44444444-4444-4444-8444-444444444444','11111111-1111-4111-8111-111111111111','file host','active')`, nil},
		{`insert into installations(id,host_id,owner_user_id,public_jwk,public_key_thumbprint) values('55555555-5555-4555-8555-555555555555','44444444-4444-4444-8444-444444444444','22222222-2222-4222-8222-222222222222','{}','file-installation-key')`, nil},
		{`insert into runtimes(id,installation_id,profile_ref) values($1,'55555555-5555-4555-8555-555555555555','files')`, []any{fileRuntimeID}},
		{`insert into workspaces(id,runtime_id,workspace_ref) values($1,$2,'files')`, []any{fileWorkspaceID, fileRuntimeID}},
		{`insert into sessions(id,runtime_id,workspace_id,dsh_session_id,state) values($1,$2,$3,'native-file-session','available')`, []any{session, fileRuntimeID, fileWorkspaceID}},
		{`insert into runtime_grants(runtime_id,user_id,role,scope,granted_by) values($1,'22222222-2222-4222-8222-222222222222','owner',$2,'22222222-2222-4222-8222-222222222222')`, []any{fileRuntimeID, `{"actions":["file.upload","file.download","session.read","grant.manage"],"workspaces":["` + fileWorkspaceID + `"],"sessions":[]}`}},
	}
	for _, statement := range statements {
		if _, err := database.ExecContext(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	repository, err := store.NewFileStore(postgres, files.Limits{OrganizationBytes: 1_000_000, UserBytes: 1_000_000, SessionBytes: 1_000_000, OrganizationFiles: 20, UserFiles: 20, SessionFiles: 10, UploadURLTTL: time.Minute, AbandonAfter: time.Hour, RetainFor: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	peer, storage, objects := newFileObjectPeer(t)
	scanner, scannerAddress := newFileScannerPeer(t)
	service, err := files.NewService(repository, storage, scanner, files.ServiceConfig{Workers: 2, PolicySHA256: strings.Repeat("a", 64), TaskTimeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ProbeScanner(ctx); err != nil {
		t.Fatal(err)
	}
	keys := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(response).Encode(map[string]any{"keys": []any{jose.JSONWebKey{Key: &issuer.PublicKey, KeyID: "file-issuer", Algorithm: "ES256", Use: "sig"}}})
	}))
	t.Cleanup(keys.Close)
	var handler http.Handler
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) { handler.ServeHTTP(response, request) }))
	t.Cleanup(server.Close)
	identity, err := auth.New(auth.Config{Issuer: "https://id.example.edu", Audience: "urn:dsh-files", JWKSURL: keys.URL, AllowedClients: []string{"mobile", "host-client"}, RequiredScopes: []string{"remote.access"}, PublicOrigin: server.URL, MaxTokenLifetime: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	handoffs, err := files.NewHandoffs(repository, storage, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	exports, err := files.NewExports(repository, storage, service)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(exports.Close)
	config := httpapi.Config{HostClientIDs: []string{"host-client"}, Files: service, FileHandoffs: handoffs, FileExports: exports}
	handler = httpapi.New(postgres, identity, config)
	if len(crossNode) > 0 && crossNode[0] {
		handler = fileOwnerRoutingHandler(t, ctx, postgres, identity, config)
	}
	token := func(client, jkt string) string {
		now := time.Now()
		return approvalSign(t, issuer, jose.ES256, "file-issuer", "at+jwt", map[string]any{"iss": "https://id.example.edu", "sub": "file-owner", "aud": "urn:dsh-files", "client_id": client, "jti": "file-access-" + client + jkt, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "scope": "remote.access", "cnf": map[string]any{"jkt": jkt}}, nil)
	}
	caller := &fileHTTPCaller{t: t, ctx: ctx, client: server.Client(), base: server.URL, key: proof, jwk: proofJWK}
	second := &fileHTTPCaller{t: t, ctx: ctx, client: server.Client(), base: server.URL, key: secondProof, jwk: secondJWK}
	return &fileHTTPFixture{ctx: ctx, database: database, service: service, exports: exports, peer: peer, objects: objects, server: server, caller: caller, second: second, token: token("mobile", proofJKT), secondToken: token("mobile", secondJKT), hostToken: token("host-client", proofJKT), session: session, scannerAddress: scannerAddress, jwksURL: keys.URL}
}
func (fixture *fileHTTPFixture) register(t *testing.T, data []byte) (files.UploadPrepared, map[string]any) {
	t.Helper()
	fixture.counter++
	sum := sha256.Sum256(data)
	body := map[string]any{"request_id": fmt.Sprintf("00000000-0000-4000-8000-%012x", fixture.counter), "name": "PRIVATE_UPLOAD_资料.bin", "size_bytes": len(data), "sha256": hex.EncodeToString(sum[:])}
	code, raw := fixture.caller.call(fixture.token, "POST", "/v1/runtimes/"+fileRuntimeID+"/sessions/"+fixture.session+"/files", body)
	var response struct {
		Data files.UploadPrepared `json:"data"`
	}
	if code != 201 || json.Unmarshal(raw, &response) != nil || response.Data.Upload == nil {
		t.Fatalf("file registration status=%d", code)
	}
	return response.Data, body
}
func (fixture *fileHTTPFixture) upload(t *testing.T, prepared files.UploadPrepared, data []byte) {
	t.Helper()
	request, err := http.NewRequestWithContext(fixture.ctx, prepared.Upload.Method, prepared.Upload.URL, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range prepared.Upload.Headers {
		if !strings.EqualFold(name, "content-length") {
			request.Header.Set(name, value)
		}
	}
	response, err := fixture.objects.Client().Do(request)
	if err != nil {
		t.Fatal("object capability write failed")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatalf("object status=%d", response.StatusCode)
	}
}
func (fixture *fileHTTPFixture) status(t *testing.T, id string) files.Status {
	t.Helper()
	code, raw := fixture.caller.call(fixture.token, "GET", "/v1/files/"+id, nil)
	var response struct {
		Data struct {
			File files.Status `json:"file"`
		} `json:"data"`
	}
	if code != 200 || json.Unmarshal(raw, &response) != nil {
		t.Fatalf("file status=%d", code)
	}
	if bytes.Contains(raw, []byte("remote-files/v1/")) || bytes.Contains(raw, []byte("lease_id")) {
		t.Fatal("private authority leaked")
	}
	return response.Data.File
}

func TestPostgresFileRESTAndActualS3ScannerWorkersCompose(t *testing.T) {
	h := newFileHTTPFixture(t)
	data := bytes.Repeat([]byte("binary\x00\xff"), 1024)
	prepared, body := h.register(t, data)
	h.upload(t, prepared, data)
	path := "/v1/files/" + prepared.File.ID
	if code, _ := h.caller.call(h.token, "POST", path+"/commit", map[string]any{}); code != 202 {
		t.Fatalf("commit=%d", code)
	}
	if code, _ := h.caller.call(h.token, "POST", path+"/upload-url", map[string]any{}); code != 409 {
		t.Fatal("scanning file got a fresh raw PUT")
	}
	if processed, err := h.service.ScanNext(h.ctx); !processed || err != nil {
		t.Fatalf("file scan=%t %v", processed, err)
	}
	if status := h.status(t, prepared.File.ID); status.State != "clean" || status.SHA256 != prepared.File.SHA256 {
		t.Fatal("actual scan did not persist clean evidence")
	}
	code, raw := h.caller.call(h.token, "POST", "/v1/runtimes/"+fileRuntimeID+"/sessions/"+h.session+"/files", body)
	var duplicate struct {
		Data files.UploadPrepared `json:"data"`
	}
	_ = json.Unmarshal(raw, &duplicate)
	if code != 201 || duplicate.Data.File.ID != prepared.File.ID || duplicate.Data.Upload != nil {
		t.Fatal("idempotent registration replayed upload")
	}
	if code, _ := h.second.call(h.secondToken, "GET", path, nil); code != 403 {
		t.Fatal("second device read private upload state")
	}
	if code, _ := h.caller.call(h.hostToken, "POST", path+"/commit", map[string]any{}); code != 403 {
		t.Fatal("host OAuth client used phone file routes")
	}
	var events, records int
	var object string
	if err := h.database.QueryRowContext(h.ctx, `select (select count(*) from files),(select count(*) from control_outbox where topic='file.clean'),object_key from files where id=$1`, prepared.File.ID).Scan(&records, &events, &object); err != nil || records != 1 || events != 1 {
		t.Fatal("metadata and offer reference diverged")
	}
	h.peer.mu.Lock()
	stored := h.peer.objects["/remote-files/"+object]
	h.peer.mu.Unlock()
	actual, err := h.peer.aead.Open(nil, stored.nonce, stored.ciphertext, []byte("/remote-files/"+object))
	if err != nil || !bytes.Equal(actual, data) {
		t.Fatal("stored verified bytes differ")
	}
	for _, scenario := range []string{"missing-size", "unknown-field", "null-size"} {
		bad := map[string]any{}
		for name, value := range body {
			bad[name] = value
		}
		switch scenario {
		case "missing-size":
			delete(bad, "size_bytes")
		case "null-size":
			bad["size_bytes"] = nil
		case "unknown-field":
			bad["device_id"] = "attacker"
		}
		if code, _ := h.caller.call(h.token, "POST", "/v1/runtimes/"+fileRuntimeID+"/sessions/"+h.session+"/files", bad); code != 400 {
			t.Fatalf("unsafe %s=%d", scenario, code)
		}
	}
	oversized := map[string]any{}
	for key, value := range body {
		oversized[key] = value
	}
	oversized["request_id"] = "99999999-9999-4999-8999-999999999999"
	oversized["size_bytes"] = 1_000_001
	if code, _ := h.caller.call(h.token, "POST", "/v1/runtimes/"+fileRuntimeID+"/sessions/"+h.session+"/files", oversized); code != 429 {
		t.Fatalf("quota response=%d", code)
	}
}

func TestPostgresFileWorkerCleanupDeletesActualObjectsBeforeReleasingQuota(t *testing.T) {
	h := newFileHTTPFixture(t)
	data := []byte("expiring service object")
	prepared, _ := h.register(t, data)
	h.upload(t, prepared, data)
	if code, _ := h.caller.call(h.token, "POST", "/v1/files/"+prepared.File.ID+"/commit", map[string]any{}); code != 202 {
		t.Fatal("scan not queued")
	}
	if _, err := h.service.ScanNext(h.ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := h.database.ExecContext(h.ctx, `update files set created_at=clock_timestamp()-interval '2 days',expires_at=clock_timestamp()-interval '1 day' where id=$1`, prepared.File.ID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(h.ctx)
	done := make(chan struct{})
	go func() { h.service.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		var state string
		if err := h.database.QueryRowContext(h.ctx, `select state from files where id=$1`, prepared.File.ID).Scan(&state); err != nil {
			t.Fatal(err)
		}
		if state == "expired" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("expiry worker did not run")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Advance the persisted grace deadline only inside this owned fixture.
	if _, err := h.database.ExecContext(h.ctx, `update file_objects set cleanup_after=clock_timestamp()-interval '1 second' where file_id=$1`, prepared.File.ID); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(4 * time.Second)
	for {
		var count int64
		if err := h.database.QueryRowContext(h.ctx, `select reserved_files from file_quota_usage where kind='session'`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("cleanup did not release the final reservation")
		}
		time.Sleep(20 * time.Millisecond)
	}
	h.peer.mu.Lock()
	objects := len(h.peer.objects)
	h.peer.mu.Unlock()
	if objects != 0 {
		t.Fatal("quota was released before source/candidate deletion")
	}
}

func TestPostgresFileWorkerRejectsMalwareAndCancelsAfterGrantRevocation(t *testing.T) {
	for _, scenario := range []string{"malware", "revoked"} {
		t.Run(scenario, func(t *testing.T) {
			h := newFileHTTPFixture(t)
			data := []byte("REJECT fixture file")
			if scenario == "revoked" {
				data = []byte("ordinary file waiting for source")
			}
			prepared, _ := h.register(t, data)
			h.upload(t, prepared, data)
			if code, _ := h.caller.call(h.token, "POST", "/v1/files/"+prepared.File.ID+"/commit", map[string]any{}); code != 202 {
				t.Fatal("scan was not queued")
			}
			if scenario == "revoked" {
				h.peer.mu.Lock()
				h.peer.blockGet = true
				h.peer.mu.Unlock()
			}
			done := make(chan error, 1)
			go func() { _, err := h.service.ScanNext(h.ctx); done <- err }()
			if scenario == "revoked" {
				select {
				case <-h.peer.getStarted:
				case <-time.After(2 * time.Second):
					t.Fatal("file did not start its authenticated source read")
				}
				if _, err := h.database.ExecContext(h.ctx, `update runtime_grants set grant_version=grant_version+1`); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case err := <-done:
				if err == nil || scenario == "malware" && !errors.Is(err, files.ErrRejected) {
					t.Fatalf("invalid file completed: %v", err)
				}
			case <-time.After(8 * time.Second):
				t.Fatal("file worker ignored revoked authority")
			}
			status := h.status(t, prepared.File.ID)
			want := "content_rejected"
			if scenario == "revoked" {
				want = "access_revoked"
			}
			if status.State != "rejected" || status.ErrorCode != want {
				t.Fatalf("failed file state=%s/%s", status.State, status.ErrorCode)
			}
			var events int
			if err := h.database.QueryRowContext(h.ctx, `select count(*) from control_outbox where topic='file.clean'`).Scan(&events); err != nil || events != 0 {
				t.Fatal("failed file created a clean offer")
			}
		})
	}
}
