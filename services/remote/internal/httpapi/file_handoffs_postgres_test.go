package httpapi_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/files"
	"github.com/coder/websocket"
	jose "github.com/go-jose/go-jose/v4"
)

type fileHost struct {
	fixture                           *fileHTTPFixture
	connection                        *websocket.Conn
	key                               *ecdsa.PrivateKey
	installation, connectionID, epoch string
}

func (h *fileHost) send(t *testing.T, frame any) {
	t.Helper()
	raw, err := json.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.connection.Write(h.fixture.ctx, websocket.MessageText, raw); err != nil {
		t.Fatal(err)
	}
}
func (h *fileHost) read(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	ctx, cancel := context.WithTimeout(h.fixture.ctx, 4*time.Second)
	defer cancel()
	_, raw, err := h.connection.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var frame map[string]json.RawMessage
	if json.Unmarshal(raw, &frame) != nil {
		t.Fatal("bad file frame")
	}
	return frame
}

func connectFileHost(t *testing.T, h *fileHTTPFixture) *fileHost {
	t.Helper()
	key := approvalKey(t)
	public, jkt := approvalPublic(t, key)
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	credential := base64.RawURLEncoding.EncodeToString(secret)
	digest := sha256.Sum256([]byte(credential))
	if _, err := h.database.ExecContext(h.ctx, `update installations set public_jwk=$1,public_key_thumbprint=$2 where id='55555555-5555-4555-8555-555555555555'`, public, jkt); err != nil {
		t.Fatal(err)
	}
	if _, err := h.database.ExecContext(h.ctx, `insert into host_connection_credentials(token_sha256,installation_id,key_version,expires_at) values($1,'55555555-5555-4555-8555-555555555555',1,clock_timestamp()+interval '5 minutes')`, digest[:]); err != nil {
		t.Fatal(err)
	}
	connection, _, err := websocket.Dial(h.ctx, strings.Replace(h.server.URL, "https://", "wss://", 1)+"/v1/realtime", &websocket.DialOptions{HTTPClient: h.server.Client(), Subprotocols: []string{"dsh.remote.v1"}, HTTPHeader: http.Header{"Authorization": []string{"DSH-Host " + credential}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.CloseNow() })
	host := &fileHost{fixture: h, connection: connection, key: key, installation: "55555555-5555-4555-8555-555555555555", epoch: "99999999-9999-4999-8999-999999999999"}
	challenge := host.read(t)
	var payload struct {
		ConnectionID string `json:"connection_id"`
		ChallengeID  string `json:"challenge_id"`
		Nonce        string `json:"nonce"`
	}
	_ = json.Unmarshal(challenge["payload"], &payload)
	host.connectionID = payload.ConnectionID
	caps := []string{"connection.heartbeat.v1", "session.catalog.v1", files.HandoffCapability}
	sort.Strings(caps)
	proof := approvalSign(t, key, jose.ES256, "", "dsh-relay-handshake-proof+jwt", map[string]any{"iss": host.installation, "aud": auth.RelayHandshakeAudience, "challenge_id": payload.ChallengeID, "connection_id": payload.ConnectionID, "nonce": payload.Nonce, "runtime_id": fileRuntimeID, "runtime_epoch": host.epoch,
		"hello_sha256": auth.RelayHelloDigest("host", fileRuntimeID, host.epoch, "0.2.1-rc.2", "file-host-fixture", "test", "1", strings.Join(caps, "\n")), "iat": time.Now().Unix(), "jti": "file-host-handshake-proof-0001"}, nil)
	host.send(t, map[string]any{"v": 1, "type": "hello.proof", "payload": map[string]any{"proof": proof, "runtime_id": fileRuntimeID, "runtime_epoch": host.epoch, "dsh_version": "0.2.1-rc.2", "application_version": "file-host-fixture", "plugin_version": "test", "protocol_version": 1, "capabilities": caps}})
	if hello := host.read(t); string(hello["type"]) != `"hello.ok"` {
		t.Fatal("file host handshake refused")
	}
	host.send(t, map[string]any{"v": 1, "type": "session.catalog", "request_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "runtime_id": fileRuntimeID, "runtime_epoch": host.epoch,
		"payload": map[string]any{"mode": "snapshot", "index": 0, "complete": true, "items": []any{map[string]any{"session_id": h.session, "dsh_session_id": "native-file-session", "workspace_id": fileWorkspaceID, "state": "available", "last_persisted_seq": -1}}}})
	if ack := host.read(t); string(ack["type"]) != `"session.catalog.ack"` {
		t.Fatal("host catalog refused")
	}
	return host
}
func (host *fileHost) offer(t *testing.T) files.FileOffer {
	t.Helper()
	frame := host.read(t)
	if string(frame["type"]) != `"file.offer"` {
		t.Fatalf("unexpected host frame type=%s", frame["type"])
	}
	var offer files.FileOffer
	if json.Unmarshal(frame["payload"], &offer) != nil || offer.DownloadToken == "" {
		t.Fatal("invalid file offer")
	}
	return offer
}
func (host *fileHost) download(t *testing.T, offer files.FileOffer, signer *ecdsa.PrivateKey) (*http.Response, error) {
	t.Helper()
	uri := host.fixture.server.URL + "/v1/host-files/" + offer.HandoffID + "/content"
	ath := sha256.Sum256([]byte(offer.DownloadToken))
	proof := approvalSign(t, signer, jose.ES256, "", auth.FileReadProofType, map[string]any{"iss": host.installation, "aud": auth.FileReadAudience, "htm": "GET", "htu": uri, "runtime_id": fileRuntimeID, "runtime_epoch": host.epoch, "connection_id": host.connectionID, "handoff_id": offer.HandoffID, "file_id": offer.FileID, "ath": base64.RawURLEncoding.EncodeToString(ath[:]), "iat": time.Now().Unix(), "jti": "host-file-get-proof-00000001"}, nil)
	request, err := http.NewRequestWithContext(host.fixture.ctx, "GET", uri, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "DSH-File "+offer.DownloadToken)
	request.Header.Set("X-DSH-File-Proof", proof)
	return host.fixture.server.Client().Do(request)
}
func (h *fileHTTPFixture) cleanForHandoff(t *testing.T, data []byte) files.UploadPrepared {
	t.Helper()
	prepared, _ := h.register(t, data)
	h.upload(t, prepared, data)
	if code, _ := h.caller.call(h.token, "POST", "/v1/files/"+prepared.File.ID+"/commit", map[string]any{}); code != 202 {
		t.Fatal("scan was not queued")
	}
	if _, err := h.service.ScanNext(h.ctx); err != nil {
		t.Fatal(err)
	}
	return prepared
}

func TestFileOfferAndSenderConstrainedHTTPStreamUseCurrentHostConnection(t *testing.T) {
	h := newFileHTTPFixture(t)
	data := bytes.Repeat([]byte("verified handoff bytes\x00\xff"), 1024)
	prepared := h.cleanForHandoff(t, data)
	host := connectFileHost(t, h)
	offer := host.offer(t)
	if offer.FileID != prepared.File.ID {
		t.Fatal("offer addressed another file")
	}
	invalid, err := host.download(t, offer, approvalKey(t))
	if err != nil {
		t.Fatal(err)
	}
	_ = invalid.Body.Close()
	if invalid.StatusCode != 403 {
		t.Fatal("unregistered key read file bytes")
	}
	response, err := host.download(t, offer, host.key)
	if err != nil {
		t.Fatal(err)
	}
	received, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != 200 || !bytes.Equal(received, data) {
		t.Fatal("protected download changed bytes")
	}
	replay, err := host.download(t, offer, host.key)
	if err != nil {
		t.Fatal(err)
	}
	_ = replay.Body.Close()
	if replay.StatusCode != 403 {
		t.Fatal("single-use read ticket replayed")
	}
	host.send(t, map[string]any{"v": 1, "type": "file.staged", "request_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "runtime_id": fileRuntimeID, "runtime_epoch": host.epoch, "session_id": h.session, "payload": map[string]any{"handoff_id": offer.HandoffID, "file_id": offer.FileID, "sha256": offer.SHA256, "size_bytes": offer.SizeBytes, "name": offer.Name}})
	if ack := host.read(t); string(ack["type"]) != `"file.staged.ack"` {
		t.Fatalf("stage ack=%s", ack["type"])
	}
	var state string
	if err := h.database.QueryRowContext(h.ctx, `select state from file_handoffs where id=$1`, offer.HandoffID).Scan(&state); err != nil || state != "staged" {
		t.Fatal("stage proof was not saved")
	}
	host.send(t, map[string]any{"v": 1, "type": "file.release", "request_id": "cccccccc-cccc-4ccc-8ccc-cccccccccccc", "runtime_id": fileRuntimeID, "runtime_epoch": host.epoch, "session_id": h.session, "payload": map[string]any{"handoff_id": offer.HandoffID, "file_id": offer.FileID, "name": "not-a-release-field"}})
	if denied := host.read(t); string(denied["type"]) != `"error"` {
		t.Fatal("release accepted stage-only selectors")
	}
	host.send(t, map[string]any{"v": 1, "type": "file.release", "request_id": "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "runtime_id": fileRuntimeID, "runtime_epoch": host.epoch, "session_id": h.session, "payload": map[string]any{"handoff_id": offer.HandoffID, "file_id": offer.FileID}})
	if ack := host.read(t); string(ack["type"]) != `"file.release.ack"` {
		t.Fatal("release acknowledgement missing")
	}
}

func TestProtectedHostFileReadCancelsSourceOnCurrentGrantRevocation(t *testing.T) {
	for _, headers := range []bool{false, true} {
		t.Run(map[bool]string{false: "body", true: "headers"}[headers], func(t *testing.T) {
			testProtectedHostFileReadCancellation(t, headers)
		})
	}
}
func testProtectedHostFileReadCancellation(t *testing.T, headers bool) {
	h := newFileHTTPFixture(t)
	h.cleanForHandoff(t, []byte("waiting protected source bytes"))
	host := connectFileHost(t, h)
	offer := host.offer(t)
	h.peer.mu.Lock()
	h.peer.blockGet = true
	h.peer.blockHeaders = headers
	h.peer.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		response, err := host.download(t, offer, host.key)
		if err == nil {
			if response.StatusCode == http.StatusOK {
				_, err = io.Copy(io.Discard, response.Body)
			} else {
				err = files.ErrAccess
			}
			_ = response.Body.Close()
		}
		done <- err
	}()
	select {
	case <-h.peer.getStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("protected read did not reach object source")
	}
	if _, err := h.database.ExecContext(h.ctx, `update runtime_grants set grant_version=grant_version+1`); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("revoked source completed")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("revoked file source was not cancelled")
	}
	select {
	case <-h.peer.getCancelled:
	case <-time.After(time.Second):
		t.Fatal("source request outlived revoked authority")
	}
}
