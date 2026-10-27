package httpapi_test

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestConfiguredFileServiceProcessRunsWorkersAndShutsDownCleanly(t *testing.T) {
	binary := os.Getenv("REMOTE_TEST_SERVICE_BIN")
	if binary == "" {
		t.Skip("the explicitly built service binary is required")
	}
	h := newFileHTTPFixture(t)
	directory := t.TempDir()
	keys := filepath.Join(directory, "keys.json")
	policy := filepath.Join(directory, "clamd.conf")
	ca := filepath.Join(directory, "object-ca.pem")
	config := filepath.Join(directory, "files.json")
	write := func(path string, body []byte) {
		t.Helper()
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(keys, []byte(`{"access_key_id":"fixture-access","secret_access_key":"fixture-secret"}`))
	write(policy, []byte("LocalSocket "+h.scannerAddress+"\nStreamMaxLength 200M\nMaxFileSize 200M\nMaxScanSize 400M\nAlertExceedsMax yes\nScanArchive yes\nMaxRecursion 16\nMaxFiles 10000\nMaxScanTime 600000\n"))
	write(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h.objects.Certificate().Raw}))
	deployment := map[string]any{
		"storage": map[string]any{"endpoint": h.objects.URL, "region": "fixture-1", "bucket": "remote-files", "kms_key_id": "fixture-kms", "credentials_file": keys, "ca_file": ca},
		"scanner": map[string]any{"network": "unix", "address": h.scannerAddress, "policy_file": policy, "timeout_seconds": 8},
		"limits":  map[string]any{"organization_bytes": 1000000, "user_bytes": 1000000, "session_bytes": 1000000, "organization_files": 20, "user_files": 20, "session_files": 10, "upload_url_seconds": 60, "abandon_seconds": 3600, "retain_seconds": 86400},
		"workers": 2, "task_timeout_seconds": 10,
	}
	raw, err := json.Marshal(deployment)
	if err != nil {
		t.Fatal(err)
	}
	write(config, raw)
	dsn, err := pgx.ParseConfig(os.Getenv("REMOTE_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.database.QueryRowContext(h.ctx, `select current_database()`).Scan(&dsn.Database); err != nil {
		t.Fatal(err)
	}
	quote := func(value string) string {
		return "'" + strings.ReplaceAll(strings.ReplaceAll(value, "\\", "\\\\"), "'", "\\'") + "'"
	}
	// pgx ConnString returns the original parse input; editing Database does
	// not rewrite it. Build an explicit DSN for this test's private database.
	childDSN := "host=" + quote(dsn.Host) + " port=" + strconv.Itoa(int(dsn.Port)) + " user=" + quote(dsn.User) + " password=" + quote(dsn.Password) + " dbname=" + quote(dsn.Database) + " sslmode=disable"
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	origin := "http://" + address
	metricsListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	metricsAddress := metricsListener.Addr().String()
	_ = metricsListener.Close()
	command := exec.CommandContext(h.ctx, binary)
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "REMOTE_ISSUER=https://id.example.edu", "REMOTE_AUDIENCE=urn:dsh-files", "REMOTE_JWKS_URL=" + h.jwksURL,
		"REMOTE_CLIENT_IDS=mobile,host-client", "REMOTE_HOST_CLIENT_IDS=host-client", "REMOTE_REQUIRED_SCOPES=remote.access", "REMOTE_PUBLIC_ORIGIN=" + origin,
		"REMOTE_DATABASE_URL=" + childDSN, "REMOTE_LISTEN_ADDR=" + address, "REMOTE_FILES_CONFIG_FILE=" + config, "REMOTE_METRICS_LISTEN_ADDR=" + metricsAddress}
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			_ = command.Process.Signal(syscall.SIGTERM)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				_ = command.Process.Kill()
				<-done
			}
		}
	})
	deadline := time.Now().Add(8 * time.Second)
	for {
		response, err := http.Get(origin + "/readyz")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == 204 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("configured file service never passed readiness")
		}
		time.Sleep(20 * time.Millisecond)
	}
	h.caller.base = origin
	h.caller.client = &http.Client{Timeout: 3 * time.Second}
	h.caller.nonce = ""
	data := []byte("process worker file bytes")
	prepared, _ := h.register(t, data)
	h.upload(t, prepared, data)
	if code, _ := h.caller.call(h.token, "POST", "/v1/files/"+prepared.File.ID+"/commit", map[string]any{}); code != 202 {
		t.Fatalf("process commit=%d", code)
	}
	deadline = time.Now().Add(5 * time.Second)
	for {
		if state := h.status(t, prepared.File.ID); state.State == "clean" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("process did not run its scan workers")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// A real worker rejection must remain distinct from a confirmed clean scan.
	rejectedData := []byte("REJECT process worker private file bytes")
	rejected, _ := h.register(t, rejectedData)
	h.upload(t, rejected, rejectedData)
	if code, _ := h.caller.call(h.token, "POST", "/v1/files/"+rejected.File.ID+"/commit", map[string]any{}); code != 202 {
		t.Fatalf("process rejected-file commit=%d", code)
	}
	deadline = time.Now().Add(5 * time.Second)
	for h.status(t, rejected.File.ID).State != "rejected" {
		if time.Now().After(deadline) {
			t.Fatal("process did not persist scan rejection")
		}
		time.Sleep(20 * time.Millisecond)
	}
	metricsClient := &http.Client{Timeout: time.Second}
	t.Cleanup(metricsClient.CloseIdleConnections)
	deadline = time.Now().Add(3 * time.Second)
	for {
		response, err := metricsClient.Get("http://" + metricsAddress + "/metrics")
		if err != nil {
			t.Fatal("configured metrics listener unavailable", err)
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 512<<10))
		_ = response.Body.Close()
		if readErr != nil || response.StatusCode != 200 {
			t.Fatal("metrics scrape failed", readErr)
		}
		for _, private := range []string{"process worker file bytes", string(rejectedData), "PRIVATE_UPLOAD_", "fixture-secret", childDSN, config, prepared.File.ID, rejected.File.ID, prepared.Upload.URL, prepared.File.SHA256} {
			if strings.Contains(string(body), private) {
				t.Fatal("operational metrics exposed private application input")
			}
		}
		if strings.Contains(string(body), "dsh_remote_control_available{worker=\"outbox\"} 1") && strings.Contains(string(body), "dsh_remote_control_available{worker=\"leases\"} 1") &&
			strings.Contains(string(body), "dsh_remote_file_scan_attempt_duration_seconds_count{direction=\"to_host\",result=\"clean\"} 1\n") &&
			strings.Contains(string(body), "dsh_remote_file_scan_attempt_duration_seconds_count{direction=\"to_host\",result=\"rejected\"} 1\n") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("production control workers or file scan outcomes were not observed")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		stopped = true
		if err != nil {
			t.Fatalf("service shutdown=%v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("file workers delayed process shutdown")
	}
	if connection, err := net.DialTimeout("tcp", metricsAddress, time.Second); err == nil {
		_ = connection.Close()
		t.Fatal("metrics listener survived production service shutdown")
	}
	for _, private := range []string{"fixture-secret", prepared.Upload.URL, "PRIVATE_UPLOAD_"} {
		if strings.Contains(output.String(), private) {
			t.Fatal("service process logs exposed file data or capabilities")
		}
	}
}
