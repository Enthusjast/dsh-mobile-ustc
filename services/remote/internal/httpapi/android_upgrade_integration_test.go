package httpapi_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/httpapi"
	"dsh-mobile-ustc/services/remote/internal/releases"
	"dsh-mobile-ustc/services/remote/internal/store"
	"dsh-mobile-ustc/services/remote/internal/testsupport"
)

// The issuer/API stay on the host while Android replaces and kills its own process.
func TestAndroidAppSelfUpgradePreservesIdentityAndData(t *testing.T) {
	serial, receiptPath := os.Getenv("REMOTE_TEST_ANDROID_UPGRADE_SERIAL"), os.Getenv("REMOTE_TEST_ANDROID_UPGRADE_RECEIPT")
	if serial == "" || receiptPath == "" {
		t.Skip("explicit full-APK upgrade fixture required")
	}
	cluster := os.Getenv("REMOTE_TEST_CLUSTER_ROOT")
	if cluster == "" {
		t.Fatal("private cluster required")
	}
	repo, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	var receipt struct {
		Version  int    `json:"v"`
		Kind     string `json:"kind"`
		Baseline struct {
			SHA256 string `json:"sha256"`
			Signer string `json:"signing_cert_sha256"`
		} `json:"baseline"`
		Candidate struct {
			Path    string `json:"path"`
			Package string `json:"package_name"`
			Version int64  `json:"version_code"`
			Name    string `json:"version_name"`
			Size    int64  `json:"size_bytes"`
			SHA256  string `json:"sha256"`
			Signer  string `json:"signing_cert_sha256"`
		} `json:"candidate"`
	}
	if json.Unmarshal(raw, &receipt) != nil || receipt.Version != 1 || receipt.Kind != "full-executable-app-upgrade-fixture" || receipt.Candidate.Package != "cn.edu.ustc.dsh.mobile" || receipt.Candidate.Version != 2 || receipt.Candidate.Signer != receipt.Baseline.Signer {
		t.Fatal("full executable same-signer v2 receipt required")
	}
	path, err := filepath.EvalSymlinks(receipt.Candidate.Path)
	if err != nil {
		t.Fatal(err)
	}
	local, _ := filepath.Abs(filepath.Join(repo, ".local"))
	if !strings.HasPrefix(path, local+string(os.PathSeparator)) {
		t.Fatal("candidate outside local fixture outputs")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != receipt.Candidate.Size {
		t.Fatal("candidate size mismatch")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil || hex.EncodeToString(hash.Sum(nil)) != receipt.Candidate.SHA256 {
		t.Fatal("candidate bytes mismatch")
	}
	_, db := testsupport.PostgresDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	postgres := &store.Postgres{DB: db}
	const org = "11111111-1111-4111-8111-111111111111"
	const user = "22222222-2222-4222-8222-222222222222"
	const host = "33333333-3333-4333-8333-333333333333"
	const installation = "44444444-4444-4444-8444-444444444444"
	const runtimeID = "55555555-5555-4555-8555-555555555555"
	const workspace = "77777777-7777-4777-8777-777777777777"
	key := approvalKey(t)
	public, jkt := approvalPublic(t, key)
	oidc := &androidOIDCFixture{t: t, secret: androidSecret(t), key: approvalKey(t), codes: map[string]androidAuthorization{}, proofs: map[string]bool{}}
	var handler *httpapi.Handler
	var downloads, releaseReads atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fixture/full-v2.apk" {
			if r.Method != http.MethodGet || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "" || r.Header.Get("DPoP") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Range") != "" {
				http.Error(w, "invalid anonymous APK request", 400)
				return
			}
			downloads.Add(1)
			w.Header().Set("Content-Type", "application/vnd.android.package-archive")
			w.Header().Set("Cache-Control", "no-store")
			// Each request owns its offset; the verified host file is never rewritten.
			reader, err := os.Open(path)
			if err != nil {
				http.Error(w, "fixture unavailable", 503)
				return
			}
			defer reader.Close()
			http.ServeContent(w, r, "full-v2.apk", info.ModTime(), reader)
			return
		}
		if r.URL.Path == "/v1/app/releases/latest" {
			releaseReads.Add(1)
		}
		if !oidc.serve(w, r) {
			handler.ServeHTTP(w, r)
		}
	}))
	defer server.Close()
	oidc.origin, oidc.issuer = server.URL, server.URL+"/issuer"
	for _, row := range []struct {
		query string
		args  []any
	}{
		{`insert into orgs(id,slug,name) values($1,'android-upgrade','Android upgrade fixture')`, []any{org}},
		{`insert into users(id,issuer,subject) values($1,$2,'android-fixture')`, []any{user, oidc.issuer}},
		{`insert into org_memberships(org_id,user_id,role) values($1,$2,'member')`, []any{org, user}},
		{`insert into hosts(id,org_id,alias,state) values($1,$2,'Upgrade fixture offline host','active')`, []any{host, org}},
		{`insert into installations(id,host_id,owner_user_id,public_jwk,public_key_thumbprint) values($1,$2,$3,$4::jsonb,$5)`, []any{installation, host, user, string(public), jkt}},
		{`insert into runtimes(id,installation_id,profile_ref,protocol_version) values($1,$2,'upgrade-fixture',1)`, []any{runtimeID, installation}},
		{`insert into workspaces(id,runtime_id,workspace_ref) values($1,$2,'upgrade-workspace')`, []any{workspace, runtimeID}},
		{`insert into runtime_grants(runtime_id,user_id,role,scope,granted_by) values($1,$2,'operator',$3::jsonb,$2)`, []any{runtimeID, user, `{"actions":["host.list","session.list","session.read","message.submit","command.status"],"workspaces":["` + workspace + `"],"sessions":[]}`}},
	} {
		if _, err := db.ExecContext(ctx, row.query, row.args...); err != nil {
			t.Fatal(err)
		}
	}
	identity, err := auth.New(auth.Config{Issuer: oidc.issuer, Audience: "urn:dsh-android-relay", JWKSURL: server.URL + "/jwks", AllowedClients: []string{"mobile"}, RequiredScopes: []string{"remote.access"}, PublicOrigin: server.URL, MaxTokenLifetime: 15 * time.Minute, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	catalogBytes, _ := json.Marshal(map[string]any{"v": 1, "package_name": receipt.Candidate.Package, "download_origins": []string{server.URL}, "supported_client_versions": map[string]int{"minimum": 1, "maximum": 2}, "publications": []any{map[string]any{"organization_ids": []string{org}, "release": map[string]any{
		"release_id": "99999999-9999-4999-8999-999999999999", "version_code": 2, "version_name": receipt.Candidate.Name, "package_name": receipt.Candidate.Package, "sha256": receipt.Candidate.SHA256, "size_bytes": receipt.Candidate.Size, "signing_cert_sha256": receipt.Candidate.Signer, "download_url": server.URL + "/fixture/full-v2.apk", "minimum_protocol_version": 1, "maximum_protocol_version": 1, "minimum_android_api": 26, "rollout_basis_points": 10000, "release_notes": "Full executable upgrade acceptance fixture"}}}})
	catalog, err := releases.Parse(catalogBytes)
	if err != nil {
		t.Fatal(err)
	}
	handler = httpapi.New(postgres, identity, httpapi.Config{Releases: catalog})
	directory, err := os.MkdirTemp(cluster, "android-upgrade-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	input := map[string]any{"v": 1, "secret": oidc.secret, "ca_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})),
		"deployment": map[string]any{"issuer": oidc.issuer, "client_id": "mobile", "redirect_uri": "cn.edu.ustc.dsh.mobile:/oauth2redirect", "resource": "urn:dsh-android-relay", "audience": "urn:dsh-android-relay", "remote_origin": server.URL, "organization_id": org, "scopes": []string{"openid", "remote.access"}, "endpoint_origins": []string{server.URL}, "signing_algorithms": []string{"ES256"}},
		"runtime_id": runtimeID, "workspace_id": workspace, "candidate_sha256": receipt.Candidate.SHA256, "candidate_version_name": receipt.Candidate.Name, "candidate_size_bytes": receipt.Candidate.Size, "signing_cert_sha256": receipt.Candidate.Signer}
	inputPath := filepath.Join(directory, "input.json")
	raw, _ = json.Marshal(input)
	if err := os.WriteFile(inputPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, "python3", filepath.Join(repo, "tools/integration/run_app_self_upgrade.py"), "--serial", serial, "--avd", os.Getenv("REMOTE_TEST_ANDROID_AVD"), "--receipt", receiptPath, "--input", inputPath, "--result", filepath.Join(directory, "result.json"))
	command.Dir = repo
	command.Cancel = func() error { return command.Process.Signal(os.Interrupt) }
	command.WaitDelay = 10 * time.Second
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("actual self-upgrade failed: %v\n%s", err, output)
	}
	var result struct {
		State    string `json:"state"`
		Device   string `json:"device_id"`
		Proof    string `json:"proof_key_jkt"`
		Approval string `json:"approval_key_jkt"`
		SHA      string `json:"installed_sha256"`
		Attempts int    `json:"room_attempts"`
	}
	raw, err = os.ReadFile(filepath.Join(directory, "result.json"))
	if err != nil || json.Unmarshal(raw, &result) != nil || result.State != "passed" || result.SHA != receipt.Candidate.SHA256 || result.Attempts != 1 {
		t.Fatal("missing complete native upgrade result")
	}
	var count int
	if err := db.QueryRowContext(ctx, `select count(*) from devices where id=$1 and user_id=$2 and proof_key_thumbprint=$3 and approval_key_thumbprint=$4 and revoked_at is null`, result.Device, user, result.Proof, result.Approval).Scan(&count); err != nil || count != 1 {
		t.Fatal("device identity changed or disappeared after replacement", err)
	}
	if downloads.Load() != 1 || releaseReads.Load() < 3 {
		t.Fatal("missing explicit download/fresh publication checks", downloads.Load(), releaseReads.Load())
	}
	t.Log(string(output))
}
