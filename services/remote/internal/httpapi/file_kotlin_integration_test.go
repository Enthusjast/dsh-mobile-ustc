package httpapi_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

func kotlinFileTransfer(t *testing.T, ctx context.Context, h *fileHTTPFixture, body []byte, stdin io.Writer, next func(string) map[string]json.RawMessage) {
	t.Helper()
	directory, err := os.MkdirTemp(os.Getenv("REMOTE_TEST_CLUSTER_ROOT"), "kotlin-files-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	source := filepath.Join(directory, "source.bin")
	if err := os.WriteFile(source, body, 0600); err != nil {
		t.Fatal(err)
	}
	private, err := json.Marshal(jose.JSONWebKey{Key: h.caller.key})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", h.jwksURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := io.ReadAll(io.LimitReader(response.Body, 32<<10))
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	ca := func(raw []byte) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}))
	}
	config := map[string]any{"mode": "files", "runtime_id": fileRuntimeID, "session_id": h.session, "workspace_id": fileWorkspaceID, "device_id": "33333333-3333-4333-8333-333333333333",
		"proof_jwk": json.RawMessage(private), "subject": "file-owner", "access_token": h.token, "access_expires_at": time.Now().Add(4 * time.Minute).UnixMilli(), "issuer_jwks": json.RawMessage(keys),
		"ca_pem": ca(h.server.Certificate().Raw), "object_ca_pem": ca(h.objects.Certificate().Raw), "source_file": source,
		"deployment": map[string]any{"issuer": "https://id.example.edu", "client_id": "mobile", "redirect_uri": "cn.edu.ustc.dsh.mobile:/oauth2redirect", "resource": "urn:dsh-files", "audience": "urn:dsh-files", "remote_origin": h.server.URL,
			"organization_id": "11111111-1111-4111-8111-111111111111", "scopes": []string{"openid", "remote.access"}, "endpoint_origins": []string{"https://id.example.edu", h.server.URL}, "signing_algorithms": []string{"ES256"}}}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "fixture.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { h.service.Run(workerCtx); close(done) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("file workers did not stop")
		}
	}()
	java := os.Getenv("REMOTE_TEST_JAVA")
	if java == "" {
		java = "java"
	}
	command := exec.CommandContext(ctx, java, "-cp", os.Getenv("REMOTE_TEST_KOTLIN_CLASSPATH"), "cn.edu.ustc.dsh.network.RunRelayProbe", path)
	command.WaitDelay = 2 * time.Second
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("Kotlin file client failed: %v\n%s", err, output)
	}
	var result struct {
		FileID    string `json:"file_id"`
		RequestID string `json:"request_id"`
		Size      int    `json:"size_bytes"`
		SHA256    string `json:"sha256"`
	}
	found := false
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "{") && json.Unmarshal([]byte(line), &result) == nil {
			found = true
		}
	}
	expected := sha256.Sum256(body)
	if !found || result.Size != len(body) || result.SHA256 != hex.EncodeToString(expected[:]) {
		t.Fatal("Kotlin upload result changed its manifest")
	}
	uploaded := next("native.upload")
	var nativeSHA string
	_ = json.Unmarshal(uploaded["sha256"], &nativeSHA)
	if nativeSHA != result.SHA256 {
		t.Fatal("Kotlin bytes did not reach native DSH")
	}
	next("native.retired")
	if _, err := io.WriteString(stdin, "inspect\n"); err != nil {
		t.Fatal(err)
	}
	observed := next("native.message")
	var count, calls int
	_ = json.Unmarshal(observed["count"], &count)
	_ = json.Unmarshal(observed["prompt_calls"], &calls)
	if count != 1 || calls != 1 {
		t.Fatal("Kotlin file retry duplicated a native prompt")
	}
	var refs int
	if err := h.database.QueryRowContext(ctx, `select count(*) from file_message_refs where file_id=$1 and request_id=$2`, result.FileID, result.RequestID).Scan(&refs); err != nil || refs != 1 {
		t.Fatal("Kotlin command/file ownership is missing")
	}
	t.Log("actual Kotlin client / TLS Go / PostgreSQL / S3 SDK peer / scanner peer / real npm DSH attachment message passed")
}
