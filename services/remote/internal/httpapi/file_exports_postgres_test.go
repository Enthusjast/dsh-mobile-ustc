package httpapi_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/files"
	jose "github.com/go-jose/go-jose/v4"
)

func (caller *fileHTTPCaller) content(token, path string, ctx context.Context, headers http.Header) (*http.Response, error) {
	for attempt := 0; attempt < 2; attempt++ {
		ath := sha256.Sum256([]byte(token))
		var entropy [24]byte
		_, _ = rand.Read(entropy[:])
		proof := approvalSign(caller.t, caller.key, jose.ES256, "", "dpop+jwt", map[string]any{"htm": "GET", "htu": caller.base + strings.Split(path, "?")[0], "iat": time.Now().Unix(), "ath": base64.RawURLEncoding.EncodeToString(ath[:]), "jti": base64.RawURLEncoding.EncodeToString(entropy[:]), "nonce": caller.nonce}, map[jose.HeaderKey]any{"jwk": caller.jwk})
		request, err := http.NewRequestWithContext(ctx, "GET", caller.base+path, nil)
		if err != nil {
			return nil, err
		}
		request.Header.Set("Authorization", "DPoP "+token)
		request.Header.Set("DPoP", proof)
		for key, values := range headers {
			request.Header[key] = append([]string(nil), values...)
		}
		response, err := caller.client.Do(request)
		if err != nil {
			return nil, err
		}
		if nonce := response.Header.Get("DPoP-Nonce"); nonce != "" {
			caller.nonce = nonce
		}
		if response.StatusCode == 401 && strings.Contains(response.Header.Get("WWW-Authenticate"), "use_dpop_nonce") && attempt == 0 {
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			continue
		}
		return response, nil
	}
	return nil, context.DeadlineExceeded
}

func prepareHTTPExport(t *testing.T, h *fileHTTPFixture, body []byte) (files.UploadPrepared, *fileHost) {
	t.Helper()
	host := connectFileHost(t, h)
	_, jkt := approvalPublic(t, h.caller.key)
	actor := files.Actor{Issuer: "https://id.example.edu", Subject: "file-owner", DeviceID: "33333333-3333-4333-8333-333333333333", ProofKeyJKT: jkt}
	sha := sha256.Sum256(body)
	prepared, err := h.exports.Register(h.ctx, actor, files.HostBinding{InstallationID: host.installation, KeyVersion: 1, RuntimeID: fileRuntimeID, RuntimeEpoch: host.epoch, ConnectionID: host.connectionID, CredentialExpiresAt: time.Now().Add(5 * time.Minute)},
		files.ExportRegistration{Origin: "session_attachment", RequestID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaab", RuntimeID: fileRuntimeID, SessionID: h.session, SourceID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", Name: "PRIVATE_EXPORT_资料.bin", SizeBytes: int64(len(body)), SHA256: hex.EncodeToString(sha[:]), SourceExpiresAt: time.Now().Add(2 * time.Minute)})
	if err != nil || prepared.Upload == nil {
		t.Fatalf("export preparation=%v", err)
	}
	return prepared, host
}
func commitHTTPExport(t *testing.T, h *fileHTTPFixture, host *fileHost, prepared files.UploadPrepared) {
	t.Helper()
	_, jkt := approvalPublic(t, h.caller.key)
	_, err := h.exports.Commit(h.ctx, files.Actor{Issuer: "https://id.example.edu", Subject: "file-owner", DeviceID: "33333333-3333-4333-8333-333333333333", ProofKeyJKT: jkt},
		files.HostBinding{InstallationID: host.installation, KeyVersion: 1, RuntimeID: fileRuntimeID, RuntimeEpoch: host.epoch, ConnectionID: host.connectionID, CredentialExpiresAt: time.Now().Add(5 * time.Minute)}, prepared.File.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.service.ScanNext(h.ctx); err != nil {
		t.Fatal(err)
	}
}

func TestProtectedExportStreamsScannedBytesWithCurrentDeviceAuthority(t *testing.T) {
	h := newFileHTTPFixture(t)
	body := bytes.Repeat([]byte("verified exported bytes\x00\xff"), 4000)
	prepared, host := prepareHTTPExport(t, h, body)
	path := "/v1/files/" + prepared.File.ID + "/content"
	before, err := h.caller.content(h.token, path, h.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = before.Body.Close()
	if before.StatusCode == 200 {
		t.Fatal("unscanned export reached the phone")
	}
	h.upload(t, prepared, body)
	commitHTTPExport(t, h, host, prepared)
	response, err := h.caller.content(h.token, path, h.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != 200 || !bytes.Equal(actual, body) {
		t.Fatal("scanned download changed bytes")
	}
	_, params, err := mime.ParseMediaType(response.Header.Get("Content-Disposition"))
	if err != nil || params["filename"] != prepared.File.Name || response.Header.Get("Content-Length") != strconv.Itoa(len(body)) || response.Header.Get("X-DSH-Content-SHA256") != prepared.File.SHA256 || response.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("download response lost its exact manifest")
	}
	status := h.status(t, prepared.File.ID)
	if status.Direction != "from_host" || status.Delivery != nil {
		t.Fatal("export was mislabeled as a Host message attachment")
	}
	code, raw := h.caller.call(h.token, "GET", "/v1/file-exports/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaab", nil)
	var restored struct {
		Data struct {
			File files.Status `json:"file"`
		} `json:"data"`
	}
	if code != 200 || json.Unmarshal(raw, &restored) != nil || restored.Data.File.ID != prepared.File.ID {
		t.Fatal("original request did not reconcile after losing registration response")
	}
	for _, caller := range []struct {
		client *fileHTTPCaller
		token  string
	}{{h.second, h.secondToken}, {h.caller, h.hostToken}} {
		denied, err := caller.client.content(caller.token, path, h.ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = denied.Body.Close()
		if denied.StatusCode == 200 {
			t.Fatal("another device or Host OAuth client read a private export")
		}
	}
	for _, selector := range []struct {
		path    string
		headers http.Header
	}{{path, http.Header{"Range": []string{"bytes=1-2"}}}, {path + "?object_key=private", nil}} {
		denied, err := h.caller.content(h.token, selector.path, h.ctx, selector.headers)
		if err != nil {
			t.Fatal(err)
		}
		_ = denied.Body.Close()
		if denied.StatusCode == 200 {
			t.Fatal("download accepted a partial/raw object selector")
		}
	}
	if code, _ := h.caller.call(h.token, "POST", "/v1/files/"+prepared.File.ID+"/upload-url", map[string]any{}); code < 400 {
		t.Fatal("phone obtained an export upload capability")
	}
	var served int
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		_ = h.database.QueryRowContext(h.ctx, `select count(*) from audit_log where action='file.export_download' and result='served'`).Scan(&served)
		if served == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if served != 1 {
		t.Fatal("served bytes lack an export audit")
	}
}

func TestProtectedExportRevocationCancelsPendingObjectHeaders(t *testing.T) {
	h := newFileHTTPFixture(t)
	prepared, host := prepareHTTPExport(t, h, []byte("private exported bytes"))
	h.upload(t, prepared, []byte("private exported bytes"))
	commitHTTPExport(t, h, host, prepared)
	h.peer.mu.Lock()
	h.peer.blockHeaders = true
	h.peer.mu.Unlock()
	worker := *h.caller
	done := make(chan *http.Response, 1)
	failed := make(chan error, 1)
	go func() {
		response, err := worker.content(h.token, "/v1/files/"+prepared.File.ID+"/content", h.ctx, nil)
		if err != nil {
			failed <- err
		} else {
			done <- response
		}
	}()
	select {
	case <-h.peer.getStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("download did not request its object")
	}
	if _, err := h.database.ExecContext(h.ctx, `update devices set revoked_at=clock_timestamp() where id='33333333-3333-4333-8333-333333333333'`); err != nil {
		t.Fatal(err)
	}
	select {
	case response := <-done:
		_ = response.Body.Close()
		if response.StatusCode == 200 {
			t.Fatal("revoked object became downloadable")
		}
	case <-failed:
	case <-time.After(2 * time.Second):
		t.Fatal("revocation did not cancel pending headers")
	}
}

func TestProtectedExportRejectsMalwareAndNeverTreatsAnUploadedObjectAsClean(t *testing.T) {
	h := newFileHTTPFixture(t)
	body := files.ScannerTestPattern()
	prepared, host := prepareHTTPExport(t, h, body)
	h.upload(t, prepared, body)
	_, jkt := approvalPublic(t, h.caller.key)
	if _, err := h.exports.Commit(h.ctx, files.Actor{Issuer: "https://id.example.edu", Subject: "file-owner", DeviceID: "33333333-3333-4333-8333-333333333333", ProofKeyJKT: jkt},
		files.HostBinding{InstallationID: host.installation, KeyVersion: 1, RuntimeID: fileRuntimeID, RuntimeEpoch: host.epoch, ConnectionID: host.connectionID, CredentialExpiresAt: time.Now().Add(5 * time.Minute)}, prepared.File.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.service.ScanNext(h.ctx); err == nil {
		t.Fatal("scanner accepted rejected bytes")
	}
	response, err := h.caller.content(h.token, "/v1/files/"+prepared.File.ID+"/content", h.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode == 200 || h.status(t, prepared.File.ID).State != "rejected" {
		t.Fatal("malware became a clean download")
	}
}

func TestProtectedExportStopsAnActiveBodyAfterGrantChange(t *testing.T) {
	h := newFileHTTPFixture(t)
	body := bytes.Repeat([]byte("owned export payload\x00"), 24000)
	prepared, host := prepareHTTPExport(t, h, body)
	h.upload(t, prepared, body)
	commitHTTPExport(t, h, host, prepared)
	h.peer.mu.Lock()
	h.peer.pauseAfter = 128 * 1024
	h.peer.mu.Unlock()
	response, err := h.caller.content(h.token, "/v1/files/"+prepared.File.ID+"/content", h.ctx, nil)
	if err != nil || response.StatusCode != 200 {
		t.Fatalf("stream did not begin: %v", err)
	}
	defer response.Body.Close()
	first := make([]byte, 1024)
	if _, err := io.ReadFull(response.Body, first); err != nil {
		t.Fatal(err)
	}
	if _, err := h.database.ExecContext(h.ctx, `update runtime_grants set grant_version=grant_version+1 where runtime_id=$1`, fileRuntimeID); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := io.Copy(io.Discard, response.Body); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("stale grant stream reached a complete response")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("active body outlived the original grant generation")
	}
	select {
	case <-h.peer.getCancelled:
	case <-time.After(time.Second):
		t.Fatal("upstream object body remained active")
	}
}

func TestProtectedExportWithholdsCorruptedCommittedBytes(t *testing.T) {
	h := newFileHTTPFixture(t)
	body := []byte("committed source bytes")
	prepared, host := prepareHTTPExport(t, h, body)
	h.upload(t, prepared, body)
	commitHTTPExport(t, h, host, prepared)
	var key string
	if err := h.database.QueryRowContext(h.ctx, `select object_key from files where id=$1`, prepared.File.ID).Scan(&key); err != nil {
		t.Fatal(err)
	}
	path := "/remote-files/" + key
	h.peer.mu.Lock()
	object := h.peer.objects[path]
	changed := bytes.Repeat([]byte("x"), len(body))
	object.nonce = make([]byte, h.peer.aead.NonceSize())
	_, _ = rand.Read(object.nonce)
	object.ciphertext = h.peer.aead.Seal(nil, object.nonce, changed, []byte(path))
	sha := sha256.Sum256(changed)
	object.checksum = base64.StdEncoding.EncodeToString(sha[:])
	h.peer.objects[path] = object
	h.peer.mu.Unlock()
	response, err := h.caller.content(h.token, "/v1/files/"+prepared.File.ID+"/content", h.ctx, nil)
	if err == nil {
		actual, readErr := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if readErr == nil && response.StatusCode == 200 && len(actual) == len(body) {
			t.Fatal("object service checksum replaced the immutable export manifest")
		}
	}
	var served int
	if err := h.database.QueryRowContext(h.ctx, `select count(*) from audit_log where action='file.export_download' and result='served'`).Scan(&served); err != nil || served != 0 {
		t.Fatal("corrupt bytes were audited as served")
	}
}
