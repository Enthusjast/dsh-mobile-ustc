package httpapi_test

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/httpapi"
	"dsh-mobile-ustc/services/remote/internal/store"
	"dsh-mobile-ustc/services/remote/internal/testsupport"
	jose "github.com/go-jose/go-jose/v4"
)

// DPoP htu binds the endpoint, never its query; query selectors still travel on
// the actual HTTP request and are validated by the production directory API.
func directoryMetadataGET(caller *fileHTTPCaller, token, path string) (int, json.RawMessage) {
	caller.t.Helper()
	for attempt := range 2 {
		ath := sha256.Sum256([]byte(token))
		proof := approvalSign(caller.t, caller.key, jose.ES256, "", "dpop+jwt", map[string]any{
			"htm": "GET", "htu": caller.base + strings.Split(path, "?")[0], "iat": time.Now().Unix(),
			"ath": base64.RawURLEncoding.EncodeToString(ath[:]), "jti": exportTestUUID(caller.t), "nonce": caller.nonce,
		}, map[jose.HeaderKey]any{"jwk": caller.jwk})
		request, err := http.NewRequestWithContext(caller.ctx, "GET", caller.base+path, nil)
		if err != nil {
			caller.t.Fatal(err)
		}
		request.Header.Set("Authorization", "DPoP "+token)
		request.Header.Set("DPoP", proof)
		response, err := caller.client.Do(request)
		if err != nil {
			caller.t.Fatal(err)
		}
		raw, err := io.ReadAll(response.Body)
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
		return response.StatusCode, raw
	}
	caller.t.Fatal("directory DPoP nonce challenge did not settle")
	return 0, nil
}

// This opt-in composition never inserts sessions or directory_metadata. Both
// are produced by the normal native DSH Host catalog over authenticated TLS.
func TestDirectoryMetadataNativeHostHTTPAuthorizationAndWithdrawal(t *testing.T) {
	if os.Getenv("REMOTE_TEST_CLUSTER_ROOT") == "" {
		t.Skip("requires explicit isolated PostgreSQL/native DSH runner")
	}
	_, database := testsupport.PostgresDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	postgres := &store.Postgres{DB: database}
	const issuer = "https://id.metadata-fixture.invalid"
	org, ownerID, viewerID := exportTestUUID(t), exportTestUUID(t), exportTestUUID(t)
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`insert into orgs(id,slug,name) values($1,'native-metadata','Native metadata fixture')`, []any{org}},
		{`insert into users(id,issuer,subject) values($1,$3,'metadata-owner'),($2,$3,'metadata-viewer')`, []any{ownerID, viewerID, issuer}},
		{`insert into org_memberships(org_id,user_id,role) values($1,$2,'admin'),($1,$3,'member')`, []any{org, ownerID, viewerID}},
	} {
		if _, err := database.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	ownerKey, viewerKey, hostKey, signing := approvalKey(t), approvalKey(t), approvalKey(t), approvalKey(t)
	ownerJWK, ownerJKT := approvalPublic(t, ownerKey)
	viewerJWK, viewerJKT := approvalPublic(t, viewerKey)
	hostJWK, hostJKT := approvalPublic(t, hostKey)
	register := func(subject string, key *ecdsa.PrivateKey) string {
		t.Helper()
		proofJWK, proofJKT := approvalPublic(t, key)
		approvalJWK, approvalJKT := approvalPublic(t, approvalKey(t))
		id, err := postgres.RegisterDevice(ctx, store.DeviceRegistration{Issuer: issuer, Subject: subject, Name: subject,
			ApprovalPublicJWK: approvalJWK, ApprovalKeyThumbprint: approvalJKT, ProofPublicJWK: proofJWK, ProofKeyThumbprint: proofJKT})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	ownerDevice := register("metadata-owner", ownerKey)
	register("metadata-viewer", viewerKey)
	keys := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{jose.JSONWebKey{Key: &signing.PublicKey, KeyID: "metadata-issuer", Algorithm: "ES256", Use: "sig"}}})
	}))
	t.Cleanup(keys.Close)
	var handler http.Handler
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(server.Close)
	identity, err := auth.New(auth.Config{Issuer: issuer, Audience: "urn:dsh-metadata", JWKSURL: keys.URL,
		AllowedClients: []string{"mobile", "metadata-host"}, RequiredScopes: []string{"remote.access"}, PublicOrigin: server.URL, MaxTokenLifetime: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	handler = httpapi.New(postgres, identity, httpapi.Config{HostClientIDs: []string{"metadata-host"}})
	token := func(subject, client, jkt string) string {
		now := time.Now()
		return approvalSign(t, signing, jose.ES256, "metadata-issuer", "at+jwt", map[string]any{"iss": issuer, "sub": subject,
			"aud": "urn:dsh-metadata", "client_id": client, "jti": exportTestUUID(t), "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
			"scope": "remote.access", "cnf": map[string]any{"jkt": jkt}}, nil)
	}
	ownerToken, viewerToken, hostToken := token("metadata-owner", "mobile", ownerJKT), token("metadata-viewer", "mobile", viewerJKT), token("metadata-owner", "metadata-host", hostJKT)
	owner := &fileHTTPCaller{t: t, ctx: ctx, client: server.Client(), base: server.URL, key: ownerKey, jwk: ownerJWK}
	viewer := &fileHTTPCaller{t: t, ctx: ctx, client: server.Client(), base: server.URL, key: viewerKey, jwk: viewerJWK}
	hostCaller := &fileHTTPCaller{t: t, ctx: ctx, client: server.Client(), base: server.URL, key: hostKey, jwk: hostJWK}
	call := func(caller *fileHTTPCaller, access, method, path string, body, target any, expected int) json.RawMessage {
		t.Helper()
		var status int
		var raw json.RawMessage
		if method == "GET" {
			status, raw = directoryMetadataGET(caller, access, path)
		} else {
			status, raw = caller.call(access, method, path, body)
		}
		if status != expected {
			t.Fatalf("metadata HTTP %s %s: status=%d expected=%d", method, strings.Split(path, "?")[0], status, expected)
		}
		if status >= 400 {
			return raw
		}
		var envelope struct {
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(raw, &envelope); err != nil {
			t.Fatal(err)
		}
		if target != nil {
			if err := json.Unmarshal(envelope.Data, target); err != nil {
				t.Fatal(err)
			}
		}
		return envelope.Data
	}
	var codeBytes [32]byte
	if _, err := rand.Read(codeBytes[:]); err != nil {
		t.Fatal(err)
	}
	code := base64.RawURLEncoding.EncodeToString(codeBytes[:])
	var enrollment store.EnrollmentCreated
	call(hostCaller, hostToken, "POST", "/v1/enrollments", map[string]any{"request_id": exportTestUUID(t), "organization_id": org,
		"alias": "Native metadata fixture", "profile_ref": "native-metadata", "dsh_version": "0.2.1-rc.2", "application_version": "native-directory-fixture",
		"plugin_version": "0.0.1", "protocol_version": 1, "installation_public_jwk": json.RawMessage(hostJWK), "code": code, "workspace_refs": []string{"fixture"}}, &enrollment, 201)
	bindingPath := "/v1/enrollments/" + enrollment.EnrollmentID
	call(owner, ownerToken, "POST", bindingPath+"/confirm", map[string]any{"code": code}, nil, 200)
	var confirmation store.EnrollmentConfirmation
	call(hostCaller, hostToken, "POST", bindingPath+"/host-confirm", map[string]any{"code": code, "confirmed_user_id": ownerID}, &confirmation, 200)
	if confirmation.State != "approved" || len(enrollment.Workspaces) != 1 {
		t.Fatal("real two-sided metadata binding was not approved")
	}
	workspaceID := enrollment.Workspaces[0].ID
	var challenge store.HostCredentialChallenge
	call(hostCaller, hostToken, "POST", "/v1/host-credentials/challenges", map[string]any{}, &challenge, 201)
	proof := approvalSign(t, hostKey, jose.ES256, "", "dsh-host-credential-proof+jwt", map[string]any{"iss": enrollment.InstallationID,
		"aud": challenge.Audience, "challenge_id": challenge.ChallengeID, "nonce": challenge.Challenge, "iat": time.Now().Unix(), "jti": exportTestUUID(t)}, nil)
	var credential store.HostConnectionCredential
	call(hostCaller, hostToken, "POST", "/v1/host-credentials", map[string]any{"challenge_id": challenge.ChallengeID, "proof": proof}, &credential, 201)
	private, err := x509.MarshalPKCS8PrivateKey(hostKey)
	if err != nil {
		t.Fatal(err)
	}
	config, _ := json.Marshal(map[string]any{"runtime": enrollment.RuntimeID, "workspace": workspaceID, "installation": enrollment.InstallationID,
		"credential": credential.Credential, "privateKey": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})), "url": server.URL})
	directory := t.TempDir()
	configPath, caPath := filepath.Join(directory, "native.json"), filepath.Join(directory, "ca.pem")
	if err := os.WriteFile(configPath, config, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	_, source, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "../../../.."))
	command := exec.CommandContext(ctx, "node", "--import", "tsx", filepath.Join(root, "tools/integration/directory-metadata-host.ts"), configPath)
	command.Dir, command.WaitDelay, command.Stderr = root, 2*time.Second, os.Stderr
	command.Env = append(os.Environ(), "NODE_EXTRA_CA_CERTS="+caPath, "NODE_NO_WARNINGS=1")
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	stopped := false
	defer func() {
		if !stopped {
			_ = stdin.Close()
			_ = command.Process.Kill()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
			}
		}
	}()
	type nativeReport struct {
		Type             string                   `json:"type"`
		SessionID        string                   `json:"session_id"`
		Metadata         *store.DirectoryMetadata `json:"metadata"`
		LastPersistedSeq int64                    `json:"last_persisted_seq"`
		PromptCalls      int                      `json:"prompt_calls"`
	}
	events := make(chan nativeReport, 16)
	go func() {
		defer close(events)
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			var event nativeReport
			if json.Unmarshal(scanner.Bytes(), &event) == nil && event.Type != "" {
				events <- event
			}
		}
	}()
	next := func(kind string) nativeReport {
		t.Helper()
		select {
		case event, ok := <-events:
			if !ok || event.Type != kind || event.PromptCalls != 0 {
				t.Fatalf("native metadata fixture did not report %s without prompting", kind)
			}
			return event
		case <-ctx.Done():
			t.Fatalf("native metadata fixture timeout: %s", kind)
		}
		return nativeReport{}
	}
	ready := next("ready")
	sessionID := ready.SessionID
	base := "/v1/runtimes/" + enrollment.RuntimeID
	directoryPath := base + "/session-directory?limit=100"
	waitStored := func(title, workspace, state string) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for {
			var gotTitle, gotWorkspace, gotState string
			err := database.QueryRowContext(ctx, `select coalesce(directory_metadata->>'title',''),coalesce(directory_metadata->>'workspace_title',''),state from sessions where id=$1 and runtime_id=$2`, sessionID, enrollment.RuntimeID).Scan(&gotTitle, &gotWorkspace, &gotState)
			if err == nil && gotTitle == title && gotWorkspace == workspace && gotState == state {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("native Host metadata did not commit expected title/workspace/state: error=%v title_match=%v workspace_match=%v state=%s", err, gotTitle == title, gotWorkspace == workspace, gotState)
			}
			time.Sleep(25 * time.Millisecond)
		}
	}
	readRow := func(caller *fileHTTPCaller, access, path string, metadata bool) store.Session {
		t.Helper()
		var page store.SessionDirectory
		raw := call(caller, access, "GET", path, nil, &page, 200)
		if page.RuntimeID != enrollment.RuntimeID || page.NextCursor != nil || len(page.Items) != 1 {
			t.Fatal("directory changed IDs or unexpected page shape")
		}
		row := page.Items[0]
		if row.ID != sessionID || metadata != (row.Metadata != nil) {
			t.Fatal("directory ID/metadata authority mismatch")
		}
		var strict struct {
			Items []map[string]json.RawMessage `json:"items"`
		}
		_ = json.Unmarshal(raw, &strict)
		keys := make([]string, 0, len(strict.Items[0]))
		for key := range strict.Items[0] {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		expected := []string{"last_persisted_seq", "session_id", "state", "updated_at", "workspace_id"}
		if metadata {
			expected = append(expected, "metadata")
			sort.Strings(expected)
		}
		if !reflect.DeepEqual(keys, expected) {
			t.Fatalf("directory compatibility keys=%v", keys)
		}
		return row
	}
	checkNames := func(report nativeReport) {
		t.Helper()
		row := readRow(owner, ownerToken, directoryPath+"&projection=names.v1", true)
		if row.WorkspaceID == nil || *row.WorkspaceID != workspaceID || !reflect.DeepEqual(row.Metadata, report.Metadata) || row.LastPersistedSeq < report.LastPersistedSeq {
			t.Fatal("HTTP names/provenance/cursor differ from current native catalog or original workspace ID")
		}
	}
	grant := func(user, role string, actions []string) {
		t.Helper()
		call(owner, ownerToken, "PUT", base+"/grants/"+user, map[string]any{"role": role, "scope": map[string]any{"actions": actions, "workspaces": []string{workspaceID}, "sessions": []string{sessionID}}}, nil, 200)
	}
	waitStored("", "原生目录验收工作区", "available")
	if ready.Metadata == nil || ready.Metadata.Title != nil || ready.Metadata.WorkspaceTitle == nil || *ready.Metadata.WorkspaceTitle != "原生目录验收工作区" {
		t.Fatal("blank native session acquired an invented name")
	}
	checkNames(ready)
	// IDs are granted explicitly; owner administration is fixture provisioning,
	// not an automatic migration/widening of an existing reader grant.
	ownerActions := []string{"grant.manage", "session.list", "session.read", "session.metadata.read"}
	grant(ownerID, "owner", ownerActions)
	grant(viewerID, "viewer", []string{"session.list", "session.read"})
	var viewerScope string
	if err := database.QueryRowContext(ctx, `select scope::text from runtime_grants where runtime_id=$1 and user_id=$2`, enrollment.RuntimeID, viewerID).Scan(&viewerScope); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(viewerScope, "session.metadata.read") {
		t.Fatal("old reader grant was automatically widened")
	}
	legacy := readRow(owner, ownerToken, directoryPath, false)
	readRow(viewer, viewerToken, directoryPath+"&projection=names.v1", false)
	legacyRaw := call(owner, ownerToken, "GET", base+"/sessions", nil, nil, 200)
	var legacyShape map[string]json.RawMessage
	_ = json.Unmarshal(legacyRaw, &legacyShape)
	var legacyItems []map[string]json.RawMessage
	_ = json.Unmarshal(legacyShape["items"], &legacyItems)
	if len(legacyShape) != 1 || len(legacyItems) != 1 || len(legacyItems[0]) != 5 || legacyItems[0]["metadata"] != nil {
		t.Fatal("legacy /sessions exact shape expanded")
	}
	for _, key := range []string{"session_id", "workspace_id", "state", "last_persisted_seq", "updated_at"} {
		if legacyItems[0][key] == nil {
			t.Fatalf("legacy /sessions missing %s", key)
		}
	}
	call(viewer, viewerToken, "GET", base+"/sessions/"+sessionID+"/read-access", nil, nil, 200)
	call(viewer, viewerToken, "GET", base+"/sessions/"+sessionID, nil, nil, 200)
	t.Log("approved two-sided enrollment; current independently signed list/read-only phone receives exact IDs-only rows and normal read authority; legacy /sessions has exactly five identifier/status keys")
	mutate := func(action string) nativeReport {
		t.Helper()
		if _, err := fmt.Fprintln(stdin, action); err != nil {
			t.Fatal(err)
		}
		return next(action)
	}
	first := mutate("rename-first")
	waitStored("原生标题第一次", "原生目录验收工作区", "available")
	checkNames(first)
	second := mutate("rename-second")
	waitStored("原生标题第二次", "更新后的原生工作区", "available")
	checkNames(second)
	if legacy.ID != sessionID {
		t.Fatal("native rename changed original session ID")
	}
	readRow(viewer, viewerToken, directoryPath+"&projection=names.v1", false)
	grant(ownerID, "owner", []string{"grant.manage", "session.list", "session.read"})
	readRow(owner, ownerToken, directoryPath+"&projection=names.v1", false)
	call(owner, ownerToken, "GET", base+"/sessions/"+sessionID+"/read-access", nil, nil, 200)
	grant(ownerID, "owner", ownerActions)
	checkNames(second)
	t.Log("actual native rename and workspace update reached Host catalog -> PostgreSQL -> opt-in names.v1 with exact native provenance and unchanged UUIDs; metadata-action revocation withheld retained names without removing read access")
	workspaceWithdrawn := mutate("withdraw-workspace")
	waitStored("原生标题第二次", "", "available")
	checkNames(workspaceWithdrawn)
	if workspaceWithdrawn.Metadata.WorkspaceTitle != nil || workspaceWithdrawn.Metadata.Title == nil {
		t.Fatal("native workspace deletion merged old workspace name")
	}
	mutate("withdraw-mapping")
	waitStored("", "", "unavailable")
	withdrawn := readRow(owner, ownerToken, directoryPath+"&projection=names.v1", false)
	if withdrawn.WorkspaceID != nil || withdrawn.State != "unavailable" {
		t.Fatal("removed managed resource retained authoritative binding")
	}
	t.Log("native workspace deletion cleared only workspace title; authenticated replacement Host with removed configured mapping published authoritative empty catalog and cleared both prior names")
	restored := mutate("restore-mapping")
	waitStored("恢复后的原生标题", "恢复后的原生工作区", "available")
	checkNames(restored)
	grant(ownerID, "owner", []string{"grant.manage", "session.read", "session.metadata.read"})
	call(owner, ownerToken, "GET", directoryPath+"&projection=names.v1", nil, nil, 403)
	grant(ownerID, "owner", ownerActions)
	checkNames(restored)
	call(owner, ownerToken, "DELETE", "/v1/devices/"+ownerDevice, nil, nil, 200)
	for _, path := range []string{directoryPath + "&projection=names.v1", directoryPath, base + "/sessions", base + "/sessions/" + sessionID + "/read-access"} {
		raw := call(owner, ownerToken, "GET", path, nil, nil, 403)
		if strings.Contains(string(raw), "原生") || strings.Contains(string(raw), "metadata") {
			t.Fatal("revoked current device released stale names")
		}
	}
	readRow(viewer, viewerToken, directoryPath+"&projection=names.v1", false)
	call(viewer, viewerToken, "GET", base+"/sessions/"+sessionID+"/read-access", nil, nil, 200)
	t.Log("restored native names still require session.list; current named-phone device revocation rejects names/legacy/read endpoints while independently authorized reader keeps IDs-only/read access; zero native prompt calls (offline fixture model, not school/provider evidence)")
	if _, err := fmt.Fprintln(stdin, "stop"); err != nil {
		t.Fatal(err)
	}
	_ = stdin.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("native metadata Host shutdown: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("native metadata Host shutdown timeout")
	}
	stopped = true
}
