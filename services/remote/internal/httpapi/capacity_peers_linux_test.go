package httpapi_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/store"
	"github.com/coder/websocket"
	jose "github.com/go-jose/go-jose/v4"
)

func capacityID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		panic("capacity fixture random source failed")
	}
	value[6], value[8] = (value[6]&15)|64, (value[8]&63)|128
	return fmt.Sprintf("%x-%x-%x-%x-%x", value[:4], value[4:6], value[6:8], value[8:10], value[10:])
}

type capacityKey struct {
	private *ecdsa.PrivateKey
	public  json.RawMessage
	jkt     string
}

func newCapacityKey() (capacityKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return capacityKey{}, err
	}
	public, err := json.Marshal(jose.JSONWebKey{Key: &key.PublicKey})
	if err != nil {
		return capacityKey{}, err
	}
	jkt, err := auth.PublicP256JWKThumbprintJSON(public)
	return capacityKey{key, public, jkt}, err
}

func capacitySign(key capacityKey, typ string, claims any, headers map[jose.HeaderKey]any) (string, error) {
	options := (&jose.SignerOptions{}).WithType(jose.ContentType(typ))
	for name, value := range headers {
		options.WithHeader(name, value)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key.private}, options)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signed, err := signer.Sign(raw)
	if err != nil {
		return "", err
	}
	return signed.CompactSerialize()
}

type capacityHTTPStats struct {
	codes     [600]atomic.Int64
	mu        sync.Mutex
	durations []time.Duration
}
type capacityAPI struct {
	http                 *http.Client
	origin, token, nonce string
	key                  capacityKey
	stats                *capacityHTTPStats
}
type capacityResponse struct {
	status int
	nonce  string
	data   json.RawMessage
	code   string
}

func (client *capacityAPI) once(ctx context.Context, method, path string, body any, key capacityKey) (capacityResponse, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return capacityResponse{}, errors.New("encode HTTP fixture")
	}
	ath := sha256.Sum256([]byte(client.token))
	proofPath, _, _ := strings.Cut(path, "?")
	proof, err := capacitySign(key, "dpop+jwt", map[string]any{"htm": method, "htu": client.origin + proofPath, "iat": time.Now().Unix(),
		"ath": base64.RawURLEncoding.EncodeToString(ath[:]), "jti": capacityID(), "nonce": client.nonce}, map[jose.HeaderKey]any{"jwk": key.public})
	if err != nil {
		return capacityResponse{}, errors.New("sign HTTP fixture")
	}
	request, err := http.NewRequestWithContext(ctx, method, client.origin+path, bytes.NewReader(raw))
	if err != nil {
		return capacityResponse{}, errors.New("construct HTTP fixture")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "DPoP "+client.token)
	request.Header.Set("DPoP", proof)
	started := time.Now()
	response, err := client.http.Do(request)
	if err != nil {
		return capacityResponse{}, errors.New("HTTP transport failed")
	}
	data, readErr := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	_ = response.Body.Close()
	if client.stats != nil {
		if response.StatusCode >= 100 && response.StatusCode < 600 {
			client.stats.codes[response.StatusCode].Add(1)
		}
		client.stats.mu.Lock()
		client.stats.durations = append(client.stats.durations, time.Since(started))
		client.stats.mu.Unlock()
	}
	if readErr != nil || len(data) > 64<<10 {
		return capacityResponse{}, errors.New("HTTP response invalid")
	}
	var envelope struct {
		Data  json.RawMessage `json:"data"`
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(data, &envelope) != nil {
		return capacityResponse{}, errors.New("HTTP envelope invalid")
	}
	return capacityResponse{response.StatusCode, response.Header.Get("DPoP-Nonce"), envelope.Data, envelope.Error.Code}, nil
}

func (client *capacityAPI) call(ctx context.Context, method, path string, body, result any, expected int) error {
	for attempt := 0; attempt < 2; attempt++ {
		response, err := client.once(ctx, method, path, body, client.key)
		if err != nil {
			return err
		}
		if response.nonce != "" {
			client.nonce = response.nonce
		}
		if attempt == 0 && response.status == 401 && response.nonce != "" {
			continue
		}
		if response.status != expected {
			endpoint := map[string]string{"/v1/host-credentials/challenges": "host_challenge", "/v1/host-credentials": "host_credential", "/v1/realtime/tickets": "phone_ticket"}[path]
			if method == "DELETE" {
				endpoint = "device_revoke"
			}
			return fmt.Errorf("HTTP endpoint=%s status=%d code=%s", endpoint, response.status, response.code)
		}
		if result != nil && json.Unmarshal(response.data, result) != nil {
			return errors.New("HTTP result invalid")
		}
		return nil
	}
	return errors.New("HTTP nonce challenge did not settle")
}

type capacityWire struct {
	V              int             `json:"v"`
	Type           string          `json:"type"`
	RequestID      string          `json:"request_id,omitempty"`
	RuntimeID      string          `json:"runtime_id,omitempty"`
	RuntimeEpoch   string          `json:"runtime_epoch,omitempty"`
	SessionID      string          `json:"session_id,omitempty"`
	SubscriptionID string          `json:"subscription_id,omitempty"`
	SyncID         string          `json:"sync_id,omitempty"`
	DeviceID       string          `json:"device_id,omitempty"`
	PayloadSHA256  string          `json:"payload_sha256,omitempty"`
	Payload        json.RawMessage `json:"payload"`
}

func capacityPayload(value any) json.RawMessage {
	raw, err := json.Marshal(value)
	if err != nil {
		panic("invalid fixture payload")
	}
	return raw
}
func capacityRead(ctx context.Context, connection *websocket.Conn) (capacityWire, error) {
	read, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	kind, raw, err := connection.Read(read)
	if err != nil {
		return capacityWire{}, fmt.Errorf("WebSocket read ended status=%d", websocket.CloseStatus(err))
	}
	var frame capacityWire
	if kind != websocket.MessageText || json.Unmarshal(raw, &frame) != nil || frame.V != 1 {
		return capacityWire{}, errors.New("WebSocket envelope invalid")
	}
	return frame, nil
}

type capacityPair struct {
	user, host, installation, runtime, epoch, workspace, session, device string
	hostKey, phoneKey, approvalKey                                       capacityKey
	hostAPI, phoneAPI                                                    *capacityAPI
	hostPeer, phonePeer                                                  *capacityPeer
	streamMu                                                             sync.Mutex
	subscription, request, syncID, attemptID                             string
	received                                                             atomic.Int64
	sent                                                                 atomic.Int64
	maxLag                                                               atomic.Int64
	sentProtocolBytes                                                    atomic.Int64
	receivedProtocolBytes                                                atomic.Int64
	body                                                                 string
	sendTimes                                                            []time.Time
	delays                                                               []time.Duration
}

func capacityConnect(ctx context.Context, client *http.Client, origin, role, credential string, key capacityKey, pair *capacityPair, extraCapabilities ...string) (*websocket.Conn, error) {
	connection, _, err := websocket.Dial(ctx, origin+"/v1/realtime", &websocket.DialOptions{HTTPClient: client, Subprotocols: []string{"dsh.remote.v1"},
		HTTPHeader: http.Header{"Authorization": []string{credential}}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return nil, errors.New("WebSocket TLS admission failed")
	}
	connection.SetReadLimit(64 << 10)
	failed := true
	defer func() {
		if failed {
			_ = connection.CloseNow()
		}
	}()
	challenge, err := capacityRead(ctx, connection)
	if err != nil || challenge.Type != "challenge" {
		return nil, errors.New("WebSocket challenge missing")
	}
	var value struct {
		ConnectionID string `json:"connection_id"`
		ChallengeID  string `json:"challenge_id"`
		Nonce        string `json:"nonce"`
	}
	if json.Unmarshal(challenge.Payload, &value) != nil || value.ConnectionID == "" || value.Nonce == "" {
		return nil, errors.New("WebSocket challenge invalid")
	}
	caps := []string{"connection.heartbeat.v1", "session.catalog.v1", "session.read.v1"}
	caps = append(caps, extraCapabilities...)
	slices.Sort(caps)
	subject, digest := pair.device, auth.RelayHelloDigest("device", pair.device, "1", strings.Join(caps, "\n"))
	hello := map[string]any{"device_id": pair.device, "protocols": []int{1}, "capabilities": caps}
	if role == "installation" {
		subject = pair.installation
		digest = auth.RelayHelloDigest("host", pair.runtime, pair.epoch, "0.2.1-rc.2", "capacity-fixture", "capacity-fixture", "1", strings.Join(caps, "\n"))
		hello = map[string]any{"runtime_id": pair.runtime, "runtime_epoch": pair.epoch, "dsh_version": "0.2.1-rc.2", "application_version": "capacity-fixture", "plugin_version": "capacity-fixture", "protocol_version": 1, "capabilities": caps}
	}
	claims := map[string]any{"iss": subject, "aud": auth.RelayHandshakeAudience, "challenge_id": value.ChallengeID, "connection_id": value.ConnectionID, "nonce": value.Nonce,
		"runtime_id": pair.runtime, "hello_sha256": digest, "iat": time.Now().Unix(), "jti": capacityID()}
	if role == "installation" {
		claims["runtime_epoch"] = pair.epoch
	}
	hello["proof"], err = capacitySign(key, "dsh-relay-handshake-proof+jwt", claims, nil)
	if err != nil {
		return nil, errors.New("WebSocket proof signing failed")
	}
	write, cancel := context.WithTimeout(ctx, 10*time.Second)
	err = connection.Write(write, websocket.MessageText, capacityPayload(map[string]any{"v": 1, "type": "hello.proof", "payload": hello}))
	cancel()
	if err != nil {
		return nil, errors.New("WebSocket proof write failed")
	}
	ack, err := capacityRead(ctx, connection)
	if err != nil || ack.Type != "hello.ok" {
		return nil, fmt.Errorf("WebSocket role=%s proof rejected", role)
	}
	failed = false
	return connection, nil
}

type capacityPeer struct {
	connection       *websocket.Conn
	role             string
	pair             *capacityPair
	ctx              context.Context
	writeMu          sync.Mutex
	pongs            chan struct{}
	snapshots        chan struct{}
	starts           chan struct{}
	closed           chan struct{}
	quiet            atomic.Bool
	revoked          atomic.Bool
	expectRevocation atomic.Bool
	heartbeats       atomic.Int64
	heartbeatMu      sync.Mutex
	lastHeartbeat    time.Time
	failure          sync.Once
	errors           chan<- error
}

func (peer *capacityPeer) send(frame capacityWire) error {
	peer.writeMu.Lock()
	defer peer.writeMu.Unlock()
	ctx, cancel := context.WithTimeout(peer.ctx, 5*time.Second)
	defer cancel()
	raw := capacityPayload(frame)
	if err := peer.connection.Write(ctx, websocket.MessageText, raw); err != nil {
		return errors.New("WebSocket write failed")
	}
	if frame.Type == "assistant.chunk" {
		peer.pair.sentProtocolBytes.Add(int64(len(raw)))
	}
	return nil
}

func (peer *capacityPeer) fail(err error) {
	if !peer.quiet.Load() {
		peer.failure.Do(func() { peer.errors <- err })
	}
}
func (peer *capacityPeer) close() {
	if peer != nil {
		peer.quiet.Store(true)
		_ = peer.connection.CloseNow()
	}
}

func (peer *capacityPeer) read() {
	defer close(peer.closed)
	for {
		kind, raw, err := peer.connection.Read(peer.ctx)
		if err != nil {
			if !peer.expectRevocation.Load() {
				peer.fail(fmt.Errorf("%s reader closed status=%d", peer.role, websocket.CloseStatus(err)))
			}
			return
		}
		var frame capacityWire
		if kind != websocket.MessageText || json.Unmarshal(raw, &frame) != nil || frame.V != 1 {
			peer.fail(errors.New("invalid data frame"))
			return
		}
		switch frame.Type {
		case "pong":
			peer.heartbeats.Add(1)
			select {
			case peer.pongs <- struct{}{}:
			default:
				peer.fail(errors.New("uncorrelated pong"))
			}
		case "access.revoked":
			if !peer.expectRevocation.Load() {
				peer.fail(errors.New("unexpected authority invalidation"))
			}
			peer.revoked.Store(true)
			peer.quiet.Store(true)
		case "session.subscribe":
			if peer.role != "installation" || frame.RuntimeID != peer.pair.runtime || frame.SessionID != peer.pair.session {
				peer.fail(errors.New("cross-resource subscription"))
				continue
			}
			peer.pair.streamMu.Lock()
			peer.pair.subscription, peer.pair.request = frame.SubscriptionID, frame.RequestID
			peer.pair.syncID, peer.pair.attemptID = capacityID(), capacityID()
			base := capacityWire{V: 1, Type: "session.snapshot", RequestID: frame.RequestID, RuntimeID: peer.pair.runtime, RuntimeEpoch: peer.pair.epoch, SessionID: peer.pair.session, SubscriptionID: frame.SubscriptionID, SyncID: peer.pair.syncID,
				Payload: capacityPayload(map[string]any{"cursor": -1, "records": []any{}, "has_more": false, "assistant": nil})}
			peer.pair.streamMu.Unlock()
			if err := peer.send(base); err != nil {
				peer.fail(err)
				continue
			}
			base.Type = "assistant.start"
			base.Payload = capacityPayload(map[string]any{"type": "start", "attemptId": peer.pair.attemptID, "revision": 1, "startedAfterSeq": -1, "turn": 0, "step": 0})
			if err := peer.send(base); err != nil {
				peer.fail(err)
			}
		case "session.snapshot":
			if peer.role != "device" || frame.RuntimeID != peer.pair.runtime || frame.SessionID != peer.pair.session {
				peer.fail(errors.New("cross-resource snapshot"))
				continue
			}
			select {
			case peer.snapshots <- struct{}{}:
			default:
				peer.fail(errors.New("duplicate snapshot"))
			}
		case "assistant.chunk":
			if peer.role != "device" || frame.RuntimeID != peer.pair.runtime || frame.RuntimeEpoch != peer.pair.epoch || frame.SessionID != peer.pair.session {
				peer.fail(errors.New("cross-resource stream"))
				continue
			}
			var payload struct {
				Index   int64  `json:"index"`
				Attempt string `json:"attemptId"`
				Chunk   struct {
					Text string `json:"text"`
				} `json:"chunk"`
			}
			peer.pair.streamMu.Lock()
			attempt, subscription, syncID, expectedBody := peer.pair.attemptID, peer.pair.subscription, peer.pair.syncID, peer.pair.body
			peer.pair.streamMu.Unlock()
			if json.Unmarshal(frame.Payload, &payload) != nil || payload.Index != peer.pair.received.Load() || payload.Attempt != attempt || frame.SubscriptionID != subscription || frame.SyncID != syncID || payload.Chunk.Text != expectedBody {
				peer.fail(errors.New("stream sequence mismatch"))
				continue
			}
			peer.pair.streamMu.Lock()
			if payload.Index < 0 || payload.Index >= int64(len(peer.pair.sendTimes)) || peer.pair.sendTimes[payload.Index].IsZero() {
				peer.pair.streamMu.Unlock()
				peer.fail(errors.New("missing source timestamp"))
				continue
			}
			peer.pair.delays[payload.Index] = time.Since(peer.pair.sendTimes[payload.Index])
			peer.pair.streamMu.Unlock()
			peer.pair.received.Add(1)
			peer.pair.receivedProtocolBytes.Add(int64(len(raw)))
		case "assistant.start":
			if peer.role != "device" || frame.RuntimeID != peer.pair.runtime || frame.SessionID != peer.pair.session {
				peer.fail(errors.New("cross-resource assistant start"))
				continue
			}
			select {
			case peer.starts <- struct{}{}:
			default:
				peer.fail(errors.New("duplicate assistant start"))
			}
		case "session.subscribed", "session.unsubscribe", "session.unsubscribed":
		case "error", "session.error", "session.closed", "runtime.changed", "server.draining":
			peer.fail(errors.New("server invalidated live workload"))
		default:
			peer.fail(errors.New("unexpected workload frame"))
		}
	}
}

func newCapacityPeer(ctx context.Context, connection *websocket.Conn, role string, pair *capacityPair, errors chan<- error) *capacityPeer {
	peer := &capacityPeer{connection: connection, role: role, pair: pair, ctx: ctx, pongs: make(chan struct{}, 1), snapshots: make(chan struct{}, 1), starts: make(chan struct{}, 1), closed: make(chan struct{}), errors: errors}
	go peer.read()
	return peer
}

func (peer *capacityPeer) heartbeat() error {
	peer.heartbeatMu.Lock()
	defer peer.heartbeatMu.Unlock()
	if wait := 1100*time.Millisecond - time.Since(peer.lastHeartbeat); wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-peer.ctx.Done():
			return peer.ctx.Err()
		case <-peer.closed:
			return errors.New("heartbeat peer closed")
		}
	}
	peer.lastHeartbeat = time.Now()
	if err := peer.send(capacityWire{V: 1, Type: "ping", Payload: json.RawMessage(`{}`)}); err != nil {
		return err
	}
	select {
	case <-peer.pongs:
		return nil
	case <-peer.closed:
		return errors.New("heartbeat peer closed")
	case <-time.After(5 * time.Second):
		return errors.New("heartbeat timed out")
	case <-peer.ctx.Done():
		return peer.ctx.Err()
	}
}

func (peer *capacityPeer) maintain() {
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-peer.ctx.Done():
				return
			case <-peer.closed:
				return
			case <-ticker.C:
				if peer.quiet.Load() {
					return
				}
				if err := peer.heartbeat(); err != nil {
					if !peer.expectRevocation.Load() {
						peer.fail(err)
					}
					return
				}
			}
		}
	}()
}

func (pair *capacityPair) admit(ctx, lifetime context.Context, httpClient *http.Client, origin string, failures chan<- error, negative bool, foreignRuntime string, checks map[string]bool) error {
	var challenge store.HostCredentialChallenge
	if err := pair.hostAPI.call(ctx, "POST", "/v1/host-credentials/challenges", map[string]any{}, &challenge, 201); err != nil {
		return err
	}
	proof, err := capacitySign(pair.hostKey, "dsh-host-credential-proof+jwt", map[string]any{"iss": pair.installation, "aud": challenge.Audience, "challenge_id": challenge.ChallengeID, "nonce": challenge.Challenge, "iat": time.Now().Unix(), "jti": capacityID()}, nil)
	if err != nil {
		return err
	}
	var credential store.HostConnectionCredential
	if err := pair.hostAPI.call(ctx, "POST", "/v1/host-credentials", map[string]any{"challenge_id": challenge.ChallengeID, "proof": proof}, &credential, 201); err != nil {
		return err
	}
	connection, err := capacityConnect(lifetime, httpClient, origin, "installation", "DSH-Host "+credential.Credential, pair.hostKey, pair)
	if err != nil {
		return err
	}
	catalog := capacityWire{V: 1, Type: "session.catalog", RequestID: capacityID(), RuntimeID: pair.runtime, RuntimeEpoch: pair.epoch,
		Payload: capacityPayload(map[string]any{"mode": "snapshot", "index": 0, "complete": true, "items": []store.SessionCatalogItem{{SessionID: pair.session, DSHSessionID: "capacity-session", WorkspaceID: &pair.workspace, State: "running", LastPersistedSeq: -1}}})}
	write, cancel := context.WithTimeout(ctx, 10*time.Second)
	err = connection.Write(write, websocket.MessageText, capacityPayload(catalog))
	cancel()
	if err != nil {
		_ = connection.CloseNow()
		return errors.New("catalog write failed")
	}
	ack, err := capacityRead(ctx, connection)
	if err != nil || ack.Type != "session.catalog.ack" {
		_ = connection.CloseNow()
		return errors.New("catalog was not admitted")
	}
	pair.hostPeer = newCapacityPeer(lifetime, connection, "installation", pair, failures)
	failed := true
	defer func() {
		if failed {
			pair.hostPeer.close()
			pair.phonePeer.close()
		}
	}()
	var ticket store.RealtimeTicket
	scope := store.GrantScope{Actions: []string{"session.read"}, Workspaces: []string{pair.workspace}, Sessions: []string{pair.session}}
	request := map[string]any{"runtime_id": pair.runtime, "scope": scope}
	if err := pair.phoneAPI.call(ctx, "POST", "/v1/realtime/tickets", request, &ticket, 201); err != nil {
		return err
	}
	if negative {
		badKey, err := newCapacityKey()
		if err != nil {
			return err
		}
		response, err := pair.phoneAPI.once(ctx, "POST", "/v1/realtime/tickets", request, badKey)
		if err != nil || response.status != 401 || response.nonce != "" {
			return errors.New("negative DPoP control failed")
		}
		checks["foreign_proof_denied"] = true
		if err := pair.phoneAPI.call(ctx, "POST", "/v1/realtime/tickets", map[string]any{"runtime_id": foreignRuntime, "scope": scope}, nil, 403); err != nil {
			return errors.New("cross-runtime control failed")
		}
		checks["foreign_runtime_denied"] = true
		parts := strings.Split(pair.phoneAPI.token, ".")
		payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var claims map[string]any
		_ = json.Unmarshal(payload, &claims)
		claims["sub"] = capacityID()
		payload, _ = json.Marshal(claims)
		parts[1] = base64.RawURLEncoding.EncodeToString(payload)
		wrong := *pair.phoneAPI
		wrong.token = strings.Join(parts, ".")
		response, err = wrong.once(ctx, "POST", "/v1/realtime/tickets", request, pair.phoneKey)
		if err != nil || response.status != 401 {
			return errors.New("tampered JWT control failed")
		}
		checks["tampered_jwt_denied"] = true
		if rejected, err := capacityConnect(ctx, httpClient, origin, "device", "DSH-Ticket "+ticket.Token, badKey, pair); err == nil {
			_ = rejected.CloseNow()
			return errors.New("foreign WSS key accepted")
		}
		checks["foreign_wss_key_denied"] = true
	}
	phone, err := capacityConnect(lifetime, httpClient, origin, "device", "DSH-Ticket "+ticket.Token, pair.phoneKey, pair)
	if err != nil {
		return err
	}
	pair.phonePeer = newCapacityPeer(lifetime, phone, "device", pair, failures)
	if negative {
		checks["ticket_survived_invalid_proof"] = true
	}
	if err := pair.hostPeer.heartbeat(); err != nil {
		return err
	}
	if err := pair.phonePeer.heartbeat(); err != nil {
		return err
	}
	pair.hostPeer.maintain()
	pair.phonePeer.maintain()
	failed = false
	return nil
}
