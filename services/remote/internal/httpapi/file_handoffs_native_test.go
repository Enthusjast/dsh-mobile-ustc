package httpapi_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestProtectedFileHandoffToRealNativeDSHAndRevocation(t *testing.T) {
	if os.Getenv("REMOTE_TEST_CLUSTER_ROOT") == "" {
		t.Skip("requires explicit isolated PostgreSQL/native DSH runner")
	}
	scenarios := []string{"revoke", "message", "reconcile", "reconcile-unknown"}
	if os.Getenv("REMOTE_TEST_KOTLIN_CLASSPATH") != "" {
		scenarios = append(scenarios, "kotlin")
	}
	for _, scenario := range scenarios {
		t.Run(scenario, func(t *testing.T) { testProtectedFileHandoffNative(t, scenario) })
	}
}

func testProtectedFileHandoffNative(t *testing.T, scenario string) {
	h := newFileHTTPFixture(t)
	allowFileMessages(t, h)
	key := approvalKey(t)
	public, thumb := approvalPublic(t, key)
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	credential := base64.RawURLEncoding.EncodeToString(secret)
	digest := sha256.Sum256([]byte(credential))
	if _, err := h.database.ExecContext(h.ctx, `update installations set public_jwk=$1,public_key_thumbprint=$2`, public, thumb); err != nil {
		t.Fatal(err)
	}
	if _, err := h.database.ExecContext(h.ctx, `insert into host_connection_credentials(token_sha256,installation_id,key_version,expires_at) values($1,'55555555-5555-4555-8555-555555555555',1,clock_timestamp()+interval '5 minutes')`, digest[:]); err != nil {
		t.Fatal(err)
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	config, err := json.Marshal(map[string]any{"runtime": fileRuntimeID, "workspace": fileWorkspaceID, "installation": "55555555-5555-4555-8555-555555555555", "credential": credential, "privateKey": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})), "url": h.server.URL})
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	configPath := filepath.Join(directory, "native.json")
	ca := filepath.Join(directory, "ca.pem")
	if err := os.WriteFile(configPath, config, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h.server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	_, source, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "../../../.."))
	ctx, cancel := context.WithTimeout(h.ctx, 30*time.Second)
	defer cancel()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, node, "--import", "tsx", filepath.Join(root, "tools/integration/file-handoff-host.ts"), configPath)
	command.WaitDelay = 2 * time.Second
	command.Dir = root
	command.Env = append(os.Environ(), "NODE_EXTRA_CA_CERTS="+ca, "NODE_NO_WARNINGS=1")
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	events := make(chan map[string]json.RawMessage, 8)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			var event map[string]json.RawMessage
			if json.Unmarshal(scanner.Bytes(), &event) == nil {
				events <- event
			}
		}
		close(events)
	}()
	go func() { done <- command.Wait() }()
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			_ = stdin.Close()
			_ = command.Process.Kill()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				_ = stdout.Close()
			}
		}
	})
	next := func(kind string) map[string]json.RawMessage {
		t.Helper()
		select {
		case event, ok := <-events:
			if !ok || string(event["type"]) != `"`+kind+`"` {
				t.Fatalf("native peer did not report %s", kind)
			}
			return event
		case <-ctx.Done():
			t.Fatalf("native peer timed out: %s", kind)
		case <-time.After(8 * time.Second):
			t.Fatalf("native peer failed to report %s", kind)
		}
		return nil
	}
	ready := next("ready")
	if json.Unmarshal(ready["session_id"], &h.session) != nil {
		t.Fatal("native session identity missing")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		var count int
		err := h.database.QueryRowContext(ctx, `select count(*) from sessions where id=$1 and state='available'`, h.session).Scan(&count)
		if err != nil {
			t.Fatal(err)
		}
		if count == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("native catalog did not reach PostgreSQL")
		}
		time.Sleep(20 * time.Millisecond)
	}
	body := bytes.Repeat([]byte("real-native protected handoff\x00\xff"), 4000)
	if scenario == "kotlin" {
		kotlinFileTransfer(t, ctx, h, body, stdin, next)
	} else {
		prepared := h.cleanForHandoff(t, body)
		uploaded := next("native.upload")
		var size int
		var sha string
		_ = json.Unmarshal(uploaded["size_bytes"], &size)
		_ = json.Unmarshal(uploaded["sha256"], &sha)
		expected := sha256.Sum256(body)
		if size != len(body) || sha != hex.EncodeToString(expected[:]) {
			t.Fatal("native receipt contains another object")
		}
		deadline = time.Now().Add(5 * time.Second)
		for {
			var count int
			err := h.database.QueryRowContext(ctx, `select count(*) from file_handoffs where file_id=$1 and state='staged'`, prepared.File.ID).Scan(&count)
			if err != nil {
				t.Fatal(err)
			}
			if count == 1 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("native stage acknowledgement did not reach PostgreSQL")
			}
			time.Sleep(20 * time.Millisecond)
		}
		if scenario != "revoke" {
			phone := connectFilePhone(t, h, h.caller, h.token, "33333333-3333-4333-8333-333333333333", true)
			request := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaad"
			phone.submit(t, request, prepared.File.ID)
			for {
				if fileMessageState(t, phone.read(t)) == "agent_queued" {
					break
				}
			}
			next("native.retired")
			expectedState := "agent_queued"
			if scenario == "reconcile" || scenario == "reconcile-unknown" {
				fault := "forget-receipt\n"
				if scenario == "reconcile-unknown" {
					fault = "forget-command\n"
					expectedState = "outcome_unknown"
				}
				if _, err := io.WriteString(stdin, fault); err != nil {
					t.Fatal(err)
				}
				next("native.receipt-forgotten")
				// Model all Relay receipts being lost while the original native
				// message remains durable; then remove every usable source object.
				if _, err := h.database.ExecContext(ctx, `update commands set state='received'`); err != nil {
					t.Fatal(err)
				}
				if _, err := h.database.ExecContext(ctx, `update files set created_at=clock_timestamp()-interval '1 day',expires_at=clock_timestamp()-interval '1 second',state='expired' where id=$1`, prepared.File.ID); err != nil {
					t.Fatal(err)
				}
				h.peer.mu.Lock()
				h.peer.objects = make(map[string]fileWireObject)
				h.peer.mu.Unlock()
			}
			phone.submit(t, request, prepared.File.ID)
			for {
				state := fileMessageState(t, phone.read(t))
				if state == expectedState {
					break
				}
				if state == "outcome_unknown" || state == "rejected" || state == "agent_queued" {
					t.Fatalf("unexpected terminal reconciliation state=%s", state)
				}
			}
			phone.submit(t, request, prepared.File.ID)
			if fileMessageState(t, phone.read(t)) != expectedState {
				t.Fatal("terminal native retry changed its result")
			}
			if _, err := io.WriteString(stdin, "inspect\n"); err != nil {
				t.Fatal(err)
			}
			observed := next("native.message")
			var count, promptCalls int
			var attachments []struct {
				SHA256 string `json:"sha256"`
				Size   int    `json:"size_bytes"`
			}
			_ = json.Unmarshal(observed["count"], &count)
			_ = json.Unmarshal(observed["prompt_calls"], &promptCalls)
			_ = json.Unmarshal(observed["files"], &attachments)
			if count != 1 || promptCalls != 1 || len(attachments) != 1 || attachments[0].SHA256 != sha || attachments[0].Size != len(body) {
				t.Fatal("native message attachment or deduplication changed")
			}
			var refs int
			if err := h.database.QueryRowContext(ctx, `select count(*) from file_message_refs where file_id=$1`, prepared.File.ID).Scan(&refs); err != nil || refs != 1 {
				t.Fatal("native file command has no durable consumption claim")
			}
		} else {
			revokedAt := time.Now()
			if _, err := h.database.ExecContext(ctx, `update runtime_grants set grant_version=grant_version+1`); err != nil {
				t.Fatal(err)
			}
			next("native.retired")
			if time.Since(revokedAt) > 4*time.Second {
				t.Fatal("native receipt outlived the revocation bound")
			}
		}
	}
	if _, err := io.WriteString(stdin, "stop\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		stopped = true
		if err != nil {
			t.Fatal("native peer did not close cleanly")
		}
	case <-ctx.Done():
		t.Fatal("native peer did not stop")
	}
	t.Log("TLS Go/PostgreSQL file offer and signed HTTP read reached real npm DSH Loader; current scenario verified revocation or file-ID message admission, consumption and retry. Object/scanner/identity/model are local fixtures.")
}
