package httpapi_test

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/files"
	"github.com/coder/websocket"
	jose "github.com/go-jose/go-jose/v4"
)

func exportTestUUID(t *testing.T) string {
	t.Helper()
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		t.Fatal(err)
	}
	value[6] = value[6]&15 | 64
	value[8] = value[8]&63 | 128
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", value[:4], value[4:6], value[6:8], value[8:10], value[10:])
}
func nativeExportError(t *testing.T, frame map[string]json.RawMessage) string {
	t.Helper()
	if string(frame["type"]) != `"file.export.error"` {
		t.Fatalf("expected export error, got %s", frame["type"])
	}
	var value struct {
		Code string `json:"code"`
	}
	if json.Unmarshal(frame["payload"], &value) != nil {
		t.Fatal("invalid export error")
	}
	return value.Code
}

func connectExportPhone(t *testing.T, h *fileHTTPFixture, caller *fileHTTPCaller, token, device string, workspace bool) *fileHost {
	t.Helper()
	return connectExportPhoneScope(t, h, caller, token, device, workspace, false, true)
}

func connectExportPhoneScope(t *testing.T, h *fileHTTPFixture, caller *fileHTTPCaller, token, device string, workspace, media, download bool) *fileHost {
	t.Helper()
	workspaces, sessions := []string{}, []string{h.session}
	if workspace {
		workspaces, sessions = []string{fileWorkspaceID}, []string{}
	}
	actions := []string{"session.read"}
	if download {
		actions = append(actions, "file.download")
	}
	code, raw := caller.call(token, "POST", "/v1/realtime/tickets", map[string]any{"runtime_id": fileRuntimeID, "scope": map[string]any{"actions": actions, "workspaces": workspaces, "sessions": sessions}})
	var reply struct {
		Data struct {
			Ticket string `json:"ticket"`
		} `json:"data"`
	}
	if code != 201 || json.Unmarshal(raw, &reply) != nil {
		t.Fatalf("export ticket=%d", code)
	}
	connection, _, err := websocket.Dial(h.ctx, strings.Replace(h.server.URL, "https://", "wss://", 1)+"/v1/realtime", &websocket.DialOptions{HTTPClient: h.server.Client(), Subprotocols: []string{"dsh.remote.v1"}, HTTPHeader: http.Header{"Authorization": []string{"DSH-Ticket " + reply.Data.Ticket}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.CloseNow() })
	phone := &fileHost{fixture: h, connection: connection, key: caller.key}
	challenge := phone.read(t)
	var data struct {
		Connection string `json:"connection_id"`
		Challenge  string `json:"challenge_id"`
		Nonce      string `json:"nonce"`
	}
	_ = json.Unmarshal(challenge["payload"], &data)
	caps := []string{"connection.heartbeat.v1", files.ExportCapability}
	if media {
		caps = append(caps, "session.read.v1", "session.media.v1", "message.images.v1")
	}
	sort.Strings(caps)
	proof := approvalSign(t, caller.key, jose.ES256, "", "dsh-relay-handshake-proof+jwt", map[string]any{"iss": device, "aud": auth.RelayHandshakeAudience, "connection_id": data.Connection, "challenge_id": data.Challenge, "nonce": data.Nonce, "runtime_id": fileRuntimeID, "hello_sha256": auth.RelayHelloDigest("device", device, "1", strings.Join(caps, "\n")), "iat": time.Now().Unix(), "jti": "export-phone-" + data.Connection}, nil)
	phone.send(t, map[string]any{"v": 1, "type": "hello.proof", "payload": map[string]any{"device_id": device, "protocols": []int{1}, "capabilities": caps, "proof": proof}})
	if hello := phone.read(t); string(hello["type"]) != `"hello.ok"` {
		t.Fatal("export phone handshake failed")
	}
	return phone
}

type nativeExportNode struct {
	ID     string `json:"source_id"`
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Origin string `json:"origin"`
}

func listNativeExports(t *testing.T, phone *fileHost, epoch, dir string) []nativeExportNode {
	t.Helper()
	payload := map[string]any{}
	if dir != "" {
		payload["directory_id"] = dir
	}
	phone.send(t, map[string]any{"v": 1, "type": "file.exports.list", "request_id": exportTestUUID(t), "runtime_id": fileRuntimeID, "runtime_epoch": epoch, "session_id": phone.fixture.session, "payload": payload})
	frame := phone.read(t)
	if string(frame["type"]) != `"file.exports.result"` {
		t.Fatalf("export list failed: type=%s payload=%s", frame["type"], frame["payload"])
	}
	var result struct {
		Items []nativeExportNode `json:"items"`
	}
	if json.Unmarshal(frame["payload"], &result) != nil {
		t.Fatal("invalid export list")
	}
	return result.Items
}
func requestNativeExport(t *testing.T, phone *fileHost, epoch, id, source string) map[string]json.RawMessage {
	t.Helper()
	phone.send(t, map[string]any{"v": 1, "type": "file.export.request", "request_id": id, "runtime_id": fileRuntimeID, "runtime_epoch": epoch, "session_id": phone.fixture.session, "payload": map[string]any{"source_id": source}})
	return phone.read(t)
}

func TestExportRelayUsesRealDSHWorkspaceAndPersistedAttachmentSources(t *testing.T) {
	runNativeExportComposition(t, false)
}

func TestExportRelayUsesRealDSHTypedImageAndRevocation(t *testing.T) {
	runNativeExportComposition(t, true)
}

func runNativeExportComposition(t *testing.T, image bool) {
	if os.Getenv("REMOTE_TEST_CLUSTER_ROOT") == "" {
		t.Skip("requires explicit isolated PostgreSQL/native DSH runner")
	}
	h := newFileHTTPFixture(t)
	key := approvalKey(t)
	public, thumb := approvalPublic(t, key)
	var secret [32]byte
	_, _ = rand.Read(secret[:])
	credential := base64.RawURLEncoding.EncodeToString(secret[:])
	hash := sha256.Sum256([]byte(credential))
	if _, err := h.database.ExecContext(h.ctx, `update installations set public_jwk=$1,public_key_thumbprint=$2`, public, thumb); err != nil {
		t.Fatal(err)
	}
	if _, err := h.database.ExecContext(h.ctx, `insert into host_connection_credentials(token_sha256,installation_id,key_version,expires_at) values($1,'55555555-5555-4555-8555-555555555555',1,clock_timestamp()+interval '5 minutes')`, hash[:]); err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"runtime": fileRuntimeID, "workspace": fileWorkspaceID, "installation": "55555555-5555-4555-8555-555555555555", "credential": credential, "privateKey": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})), "url": h.server.URL, "image": image})
	dir := t.TempDir()
	config := filepath.Join(dir, "native.json")
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(config, raw, 0600); err != nil {
		t.Fatal(err)
	}
	certs := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h.server.Certificate().Raw}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h.objects.Certificate().Raw})...)
	if err := os.WriteFile(ca, certs, 0600); err != nil {
		t.Fatal(err)
	}
	_, source, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "../../../.."))
	ctx, cancel := context.WithTimeout(h.ctx, 90*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "node", "--import", "tsx", filepath.Join(root, "tools/integration/file-export-host.ts"), config)
	command.Dir = root
	command.WaitDelay = 2 * time.Second
	command.Env = append(os.Environ(), "NODE_EXTRA_CA_CERTS="+ca, "NODE_NO_WARNINGS=1")
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			_ = stdin.Close()
			_ = command.Process.Kill()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
			}
		}
	})
	events := make(chan map[string]json.RawMessage, 8)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			var item map[string]json.RawMessage
			if json.Unmarshal(scanner.Bytes(), &item) == nil {
				events <- item
			}
		}
		close(events)
	}()
	next := func(kind string) map[string]json.RawMessage {
		t.Helper()
		select {
		case event, ok := <-events:
			if !ok || string(event["type"]) != `"`+kind+`"` {
				t.Fatalf("native export peer did not report %s", kind)
			}
			return event
		case <-ctx.Done():
			t.Fatalf("native export peer timed out: %s", kind)
		}
		return nil
	}
	ready := next("ready")
	_ = json.Unmarshal(ready["session_id"], &h.session)
	var epoch string
	for deadline := time.Now().Add(5 * time.Second); ; {
		var count int
		_ = h.database.QueryRowContext(ctx, `select count(*) from sessions where id=$1 and state='available'`, h.session).Scan(&count)
		if count == 1 {
			_ = h.database.QueryRowContext(ctx, `select epoch::text from runtimes where id=$1`, fileRuntimeID).Scan(&epoch)
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("export Host catalog was not published")
		}
		time.Sleep(20 * time.Millisecond)
	}
	worker, cancelWorkers := context.WithCancel(ctx)
	// An explicit session grant is required to issue a literal session-only
	// ticket; a workspace grant is not silently converted into one.
	if _, err := h.database.ExecContext(ctx, `update runtime_grants set scope=jsonb_set(scope,'{sessions}',jsonb_build_array($1::text)) where runtime_id=$2`, h.session, fileRuntimeID); err != nil {
		t.Fatal(err)
	}
	workersDone := make(chan struct{})
	go func() { h.service.Run(worker); close(workersDone) }()
	defer func() { cancelWorkers(); <-workersDone }()
	phone := connectExportPhone(t, h, h.caller, h.token, "33333333-3333-4333-8333-333333333333", true)
	roots := listNativeExports(t, phone, epoch, "")
	var reports string
	for _, node := range roots {
		if node.Name == "reports" {
			reports = node.ID
		}
	}
	if reports == "" {
		t.Fatal("declared export root missing")
	}
	listing := listNativeExports(t, phone, epoch, reports)
	var artifact, empty string
	for _, node := range listing {
		if node.Name == "outside-link" {
			t.Fatal("outside link became an export source")
		}
		if node.Name == "report.bin" {
			artifact = node.ID
		}
		if node.Name == "empty.bin" {
			empty = node.ID
		}
	}
	if artifact == "" {
		t.Fatal("workspace artifact missing")
	}
	request := exportTestUUID(t)
	accepted := requestNativeExport(t, phone, epoch, request, artifact)
	var result struct {
		File files.Status `json:"file"`
	}
	if string(accepted["type"]) != `"file.export.accepted"` || json.Unmarshal(accepted["payload"], &result) != nil {
		t.Fatalf("artifact export failed: type=%s payload=%s", accepted["type"], accepted["payload"])
	}
	file := result.File
	for deadline := time.Now().Add(5 * time.Second); ; {
		status := h.status(t, file.ID)
		if status.State == "clean" {
			break
		}
		if status.State == "rejected" || time.Now().After(deadline) {
			t.Fatal("native export did not scan clean")
		}
		time.Sleep(20 * time.Millisecond)
	}
	response, err := h.caller.content(h.token, "/v1/files/"+file.ID+"/content", ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != 200 {
		t.Fatal("native artifact download failed")
	}
	expected := sha256.Sum256(data)
	var sha string
	_ = json.Unmarshal(ready["artifact_sha256"], &sha)
	if hex.EncodeToString(expected[:]) != sha {
		t.Fatal("workspace source bytes changed across Relay/object/scanner/download")
	}
	retried := requestNativeExport(t, phone, epoch, request, artifact)
	var original struct {
		File files.Status `json:"file"`
	}
	_ = json.Unmarshal(retried["payload"], &original)
	if original.File.ID != file.ID {
		t.Fatal("same export request created new file")
	}
	changed := requestNativeExport(t, phone, epoch, request, exportTestUUID(t))
	if nativeExportError(t, changed) != "command.request_conflict" {
		t.Fatal("changed source reused the original request")
	}
	other := connectExportPhone(t, h, h.second, h.secondToken, "88888888-8888-4888-8888-888888888888", true)
	if frame := requestNativeExport(t, other, epoch, exportTestUUID(t), artifact); nativeExportError(t, frame) != "file.export_unavailable" {
		t.Fatalf("source ID crossed device: %s", frame["payload"])
	}
	narrow := connectExportPhone(t, h, h.caller, h.token, "33333333-3333-4333-8333-333333333333", false)
	privateRoots := listNativeExports(t, narrow, epoch, "")
	if len(privateRoots) != 1 || privateRoots[0].Origin != "session_attachment" {
		t.Fatal("session ticket enumerated workspace roots")
	}
	nativeFiles := listNativeExports(t, narrow, epoch, privateRoots[0].ID)
	var attachment string
	for _, node := range nativeFiles {
		if node.Name == "attached.bin" {
			attachment = node.ID
		}
	}
	if attachment == "" {
		t.Fatal("persisted attachment was not discoverable")
	}
	attachmentReply := requestNativeExport(t, narrow, epoch, exportTestUUID(t), attachment)
	if string(attachmentReply["type"]) != `"file.export.accepted"` {
		t.Fatalf("session attachment export failed: %s", attachmentReply["payload"])
	}
	emptyReply := requestNativeExport(t, phone, epoch, exportTestUUID(t), empty)
	var emptyFile struct {
		File files.Status `json:"file"`
	}
	_ = json.Unmarshal(emptyReply["payload"], &emptyFile)
	if string(emptyReply["type"]) != `"file.export.accepted"` || emptyFile.File.SizeBytes != 0 {
		var state, key string
		var size int64
		_ = h.database.QueryRowContext(ctx, `select state,object_key,size_bytes from files where name='empty.bin'`).Scan(&state, &key, &size)
		h.peer.mu.Lock()
		_, stored := h.peer.objects["/remote-files/"+key]
		h.peer.mu.Unlock()
		t.Fatalf("empty export failed: %s state=%s size=%d object_stored=%v", emptyReply["payload"], state, size, stored)
	}
	var count int
	if err := h.database.QueryRowContext(ctx, `select count(*) from file_exports`).Scan(&count); err != nil || count != 3 {
		t.Fatal("replay or denied request created export provenance")
	}
	_, _ = io.WriteString(stdin, "inspect\n")
	inspection := next("inspected")
	wantMessages := "1"
	if image {
		wantMessages = "2"
	}
	if string(inspection["prompt_calls"]) != "0" || string(inspection["human_messages"]) != wantMessages {
		t.Fatal("export admitted a prompt or another native message")
	}
	if image {
		var imageSHA string
		_ = json.Unmarshal(ready["image_sha256"], &imageSHA)
		exerciseNativeImageExport(t, h, epoch, imageSHA)
	}
	_, _ = io.WriteString(stdin, "stop\n")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	stopped = true
}
