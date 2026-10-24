package relay

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/approval"
	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/store"
	"github.com/coder/websocket"
)

// These stubs test routing/fencing only. The real PostgreSQL controller tests
// separately enforce cryptography, owner authority, assurance and durability.
type approvalRoutingStore struct {
	mu                               sync.Mutex
	statuses                         map[string]store.ApprovalStatus
	deny                             bool
	decideErr, issueErr, errorResult error
	decisions, leases, results       int
	principal                        auth.Principal
	decisionTicket                   store.TicketRedemption
	snapshotHook                     func()
}

func (stub *approvalRoutingStore) Register(_ context.Context, _ store.RuntimeConnection, _ int64, raw []byte) (store.ApprovalStatus, error) {
	binding, err := approval.ContextBinding(raw)
	if err != nil {
		return store.ApprovalStatus{}, err
	}
	request := binding.Context
	expires, _ := time.Parse(time.RFC3339Nano, request.ExpiresAt)
	status := store.ApprovalStatus{ApprovalID: request.ApprovalID, RuntimeID: request.RuntimeID, RuntimeEpoch: request.RuntimeEpoch, SessionID: request.SessionID,
		ExecutionID: request.ExecutionID, BindingSHA256: binding.SHA256, State: "pending", ExpiresAt: expires}
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.statuses[status.ApprovalID] = status
	return status, nil
}

func (stub *approvalRoutingStore) AuthorizeStatus(_ context.Context, ticket store.TicketRedemption, id string) (store.ApprovalStatus, error) {
	stub.mu.Lock()
	status, exists := stub.statuses[id]
	denied := stub.deny || !exists || ticket.RuntimeID != status.RuntimeID || !slices.Contains(ticket.Scope.Actions, "approval.decide") || !slices.Contains(ticket.Scope.Actions, "session.read") || !slices.Contains(ticket.Scope.Sessions, status.SessionID)
	hook := stub.snapshotHook
	stub.snapshotHook = nil
	stub.mu.Unlock()
	if denied {
		return store.ApprovalStatus{}, store.ErrAccessDenied
	}
	if hook != nil {
		hook()
	}
	return status, nil
}
func (stub *approvalRoutingStore) AuthorizeView(ctx context.Context, ticket store.TicketRedemption, id string) (store.ApprovalStatus, error) {
	return stub.AuthorizeStatus(ctx, ticket, id)
}
func (stub *approvalRoutingStore) ListPending(_ context.Context, ticket store.TicketRedemption) ([]store.ApprovalStatus, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if stub.deny || !slices.Contains(ticket.Scope.Actions, "approval.decide") || !slices.Contains(ticket.Scope.Actions, "session.read") {
		return nil, store.ErrAccessDenied
	}
	statuses := []store.ApprovalStatus{}
	for _, status := range stub.statuses {
		if status.State == "pending" && slices.Contains(ticket.Scope.Sessions, status.SessionID) {
			statuses = append(statuses, status)
		}
	}
	return statuses, nil
}
func (stub *approvalRoutingStore) Decide(_ context.Context, principal auth.Principal, ticket store.TicketRedemption, raw []byte, _ string) (store.ApprovalStatus, error) {
	binding, err := approval.ContextBinding(raw)
	if err != nil {
		return store.ApprovalStatus{}, err
	}
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.decisions++
	stub.principal = principal
	stub.decisionTicket = ticket
	if stub.decideErr != nil {
		return store.ApprovalStatus{}, stub.decideErr
	}
	status := stub.statuses[binding.Context.ApprovalID]
	status.State, status.Decision, status.PayloadSHA256 = "decision_received", "allow_once", strings.Repeat("b", 64)
	stub.statuses[status.ApprovalID] = status
	return status, nil
}
func (stub *approvalRoutingStore) Issue(context.Context, store.RuntimeConnection, int64, []byte) (string, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.leases++
	if stub.issueErr != nil {
		return "", stub.issueErr
	}
	return "e30.e30.AA", nil
}
func (stub *approvalRoutingStore) RecordResult(_ context.Context, _ store.RuntimeConnection, _ int64, result store.ApprovalHostResult) (store.ApprovalStatus, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.results++
	if stub.errorResult != nil {
		return store.ApprovalStatus{}, stub.errorResult
	}
	status := stub.statuses[result.ApprovalID]
	status.State, status.HostState, status.Outcome = "allowed", result.State, result.Outcome
	stub.statuses[status.ApprovalID] = status
	return status, nil
}

type approvalRelayFixture struct {
	server       *Server
	stub         *approvalRoutingStore
	repo         *relayTestStore
	host, device *websocket.Conn
	request      approval.Context
	raw          []byte
	connectionID string
	principal    auth.Principal
}

func newApprovalRelayFixture(t *testing.T, enabled bool, actions ...[]string) *approvalRelayFixture {
	t.Helper()
	data, err := os.ReadFile("../../../../contracts/security/approval-signatures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Context approval.Context `json:"context"`
	}
	if json.Unmarshal(data, &fixture) != nil {
		t.Fatal("invalid shared context")
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	fixture.Context.CreatedAt, fixture.Context.ExpiresAt = now.Add(-time.Second).Format("2006-01-02T15:04:05.000Z"), now.Add(2*time.Minute).Format("2006-01-02T15:04:05.000Z")
	raw, err := json.Marshal(fixture.Context)
	if err != nil {
		t.Fatal(err)
	}
	key := relayTestKey(t)
	jwk, jkt := relayTestPublicJWK(t, key)
	ticket := store.TicketRedemption{UserID: fixture.Context.HostID, DeviceID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", RuntimeID: fixture.Context.RuntimeID, GrantVersion: 1, DeviceKeyVersion: 1,
		ProofPublicJWK: jwk, ProofKeyThumbprint: jkt, ExpiresAt: now.Add(time.Minute), Scope: store.GrantScope{Actions: []string{"approval.decide", "session.read"}, Workspaces: []string{}, Sessions: []string{fixture.Context.SessionID}}}
	if len(actions) > 0 {
		ticket.Scope.Actions = append([]string{}, actions[0]...)
	}
	repo := &relayTestStore{ticket: ticket, hostCredential: store.HostCredentialIdentity{InstallationID: fixture.Context.InstallationID, KeyVersion: 1, PublicJWK: jwk, KeyThumbprint: jkt, ExpiresAt: now.Add(time.Minute)}, detached: make(chan store.RuntimeConnection, 8)}
	stub := &approvalRoutingStore{statuses: map[string]store.ApprovalStatus{}}
	var options []ApprovalConfig
	if enabled {
		options = append(options, ApprovalConfig{Control: stub, Leases: stub})
	}
	server := New(repo, options...)
	httpServer := httptest.NewServer(server)
	t.Cleanup(httpServer.Close)
	caps := append([]string{}, supportedCapabilities...)
	caps = append(caps, approvalCapability)
	caps = append(caps, approvalInvalidationCapability)
	hostCaps := caps
	if len(actions) > 1 {
		hostCaps = actions[1]
	}
	host := dialRelayHost(t, httpServer.URL, key, fixture.Context.InstallationID, fixture.Context.RuntimeID, fixture.Context.RuntimeEpoch, hostCaps...)
	device := dialRelayDevice(t, httpServer.URL, key, ticket, fixture.Context.RuntimeID, caps...)
	t.Cleanup(func() { _ = device.CloseNow(); _ = host.CloseNow() })
	server.mu.Lock()
	connectionID := ""
	for _, live := range server.connections {
		if live.peer.role == "device" {
			connectionID = live.connectionID
		}
	}
	server.mu.Unlock()
	return &approvalRelayFixture{server: server, stub: stub, repo: repo, host: host, device: device, request: fixture.Context, raw: raw, connectionID: connectionID, principal: auth.Principal{Issuer: "https://id.example.edu", Subject: "owner", ProofKeyJKT: jkt, ProofJTI: "fresh-http-proof"}}
}

func (fixture *approvalRelayFixture) register(t *testing.T) store.ApprovalStatus {
	t.Helper()
	frame := approvalFrame("approval.request", fixture.request.ApprovalID, store.ApprovalStatus{RuntimeID: fixture.request.RuntimeID, RuntimeEpoch: fixture.request.RuntimeEpoch, SessionID: fixture.request.SessionID}, map[string]json.RawMessage{"context": fixture.raw})
	writeWireFrame(t, fixture.host, frame)
	if ack := readEnvelope(t, fixture.host); ack.Type != "approval.registered" {
		t.Fatalf("registration failed: %+v", ack)
	}
	fixture.stub.mu.Lock()
	defer fixture.stub.mu.Unlock()
	return fixture.stub.statuses[fixture.request.ApprovalID]
}

func TestApprovalRoutingRequiresNegotiatedCapabilityAndExactSocketScope(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "scoped"}[enabled], func(t *testing.T) {
			fixture := newApprovalRelayFixture(t, enabled, []string{"session.read"})
			if enabled {
				fixture.register(t)
			}
			writeWireFrame(t, fixture.device, map[string]any{"v": 1, "type": "approval.subscribe", "request_id": fixture.request.ApprovalID, "runtime_id": fixture.request.RuntimeID, "payload": map[string]any{}})
			frame := readEnvelope(t, fixture.device)
			want := "protocol.unsupported"
			if enabled {
				want = "access.denied"
			}
			if frame.Type != "error" || frame.Payload["code"] != want {
				t.Fatalf("approval capability/scope leaked: %+v", frame)
			}
		})
	}
}

func TestApprovalRegistrationDetailsAndResultAcksStayBoundToTheCurrentHost(t *testing.T) {
	fixture := newApprovalRelayFixture(t, true)
	writeWireFrame(t, fixture.device, map[string]any{"v": 1, "type": "approval.subscribe", "request_id": fixture.request.ApprovalID, "runtime_id": fixture.request.RuntimeID, "payload": map[string]any{}})
	if frame := readEnvelope(t, fixture.device); frame.Type != "approval.snapshot" {
		t.Fatalf("missing empty snapshot: %+v", frame)
	}
	status := fixture.register(t)
	if frame := readEnvelope(t, fixture.device); frame.Type != "approval.reference" {
		t.Fatalf("missing scoped reference: %+v", frame)
	}
	get := approvalFrame("approval.details.get", fixture.request.ExecutionID, status, map[string]string{"approval_id": status.ApprovalID})
	writeWireFrame(t, fixture.device, get)
	request := readEnvelope(t, fixture.host)
	if request.Type != "approval.details.get" || request.RequestID == fixture.request.ExecutionID {
		t.Fatalf("host detail RPC reused phone routing identity: %+v", request)
	}
	writeWireFrame(t, fixture.host, approvalFrame("approval.details", request.RequestID, status, map[string]json.RawMessage{"context": fixture.raw}))
	if frame := readEnvelope(t, fixture.device); frame.Type != "approval.details" || frame.RequestID != fixture.request.ExecutionID {
		t.Fatalf("details lost admitted route: %+v", frame)
	}
	frame := approvalFrame("approval.result", fixture.request.ExecutionID, status, map[string]any{"approval_id": status.ApprovalID, "execution_id": status.ExecutionID, "binding_sha256": status.BindingSHA256, "decision_payload_sha256": strings.Repeat("b", 64), "state": "settled", "execution_outcome": "succeeded"})
	raw, _ := json.Marshal(frame)
	var envelope wireEnvelope
	_ = json.Unmarshal(raw, &envelope)
	digest, err := approvalResultDigest(envelope)
	if err != nil {
		t.Fatal(err)
	}
	frame["payload_sha256"] = digest
	writeWireFrame(t, fixture.host, frame)
	if ack := readEnvelope(t, fixture.host); ack.Type != "approval.result.ack" || ack.PayloadSHA256 != digest {
		t.Fatalf("result was not durably acknowledged by hash: %+v", ack)
	}
	if update := readEnvelope(t, fixture.device); update.Type != "approval.reference" {
		t.Fatalf("missing native result reference: %+v", update)
	}
	if err := fixture.server.ApplyControlEvent(t.Context(), store.ControlEvent{Topic: "approval.pending", RuntimeID: status.RuntimeID, ApprovalID: status.ApprovalID}); err != nil {
		t.Fatal(err)
	}
	if replay := readEnvelope(t, fixture.device); replay.Type != "approval.reference" || replay.Payload["status"].(map[string]any)["state"] != "allowed" {
		t.Fatalf("outbox replay revived an old pending state: %+v", replay)
	}
	frame["payload_sha256"] = strings.Repeat("c", 64)
	writeWireFrame(t, fixture.host, frame)
	if rejected := readEnvelope(t, fixture.host); rejected.Type != "error" || rejected.Payload["code"] != "protocol.invalid" {
		t.Fatalf("altered result hash accepted: %+v", rejected)
	}
}

func TestApprovalDecisionUsesFreshPrincipalAndNeverForwardsBeforeAcceptance(t *testing.T) {
	for _, scenario := range []string{"forwarded", "bad-decision", "lease-unavailable"} {
		t.Run(scenario, func(t *testing.T) {
			fixture := newApprovalRelayFixture(t, true)
			status := fixture.register(t)
			if scenario == "bad-decision" {
				fixture.stub.decideErr = approval.ErrDecision
			}
			if scenario == "lease-unavailable" {
				fixture.stub.issueErr = store.ErrDatabaseUnavailable
			}
			type response struct {
				status   store.ApprovalStatus
				delivery string
				err      error
			}
			result := make(chan response, 1)
			go func() {
				status, delivery, err := fixture.server.DecideApproval(t.Context(), fixture.principal, fixture.repo.ticket.DeviceID, fixture.connectionID, status.ApprovalID, "e30.e30.AA")
				result <- response{status, delivery, err}
			}()
			request := readEnvelope(t, fixture.host)
			writeWireFrame(t, fixture.host, approvalFrame("approval.details", request.RequestID, status, map[string]json.RawMessage{"context": fixture.raw}))
			outcome := <-result
			if scenario == "bad-decision" {
				if !errors.Is(outcome.err, approval.ErrDecision) || fixture.stub.leases != 0 {
					t.Fatalf("invalid decision reached signer: %+v", outcome)
				}
				return
			}
			if outcome.err != nil || outcome.status.State != "decision_received" {
				t.Fatalf("accepted decision lost durable state: %+v", outcome)
			}
			if fixture.stub.principal.ProofJTI != fixture.principal.ProofJTI || fixture.stub.decisionTicket.DeviceID != fixture.repo.ticket.DeviceID {
				t.Fatal("fresh principal or admitted ticket replaced by phone JSON")
			}
			if scenario == "lease-unavailable" {
				if outcome.delivery != "pending" {
					t.Fatalf("undelivered permission claimed forwarded: %+v", outcome)
				}
				return
			}
			forward := readEnvelope(t, fixture.host)
			if outcome.delivery != "forwarded" || forward.Type != "approval.decision" || forward.Payload["decision_jws"] != "e30.e30.AA" || forward.Payload["authorization_jws"] != "e30.e30.AA" {
				t.Fatalf("signed decision forwarding: %+v %+v", outcome, forward)
			}
		})
	}
}

func TestApprovalDetailRPCIsBoundedAndCancelledWithoutConsumingDecision(t *testing.T) {
	fixture := newApprovalRelayFixture(t, true)
	status := fixture.register(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, _, err := fixture.server.DecideApproval(ctx, fixture.principal, fixture.repo.ticket.DeviceID, fixture.connectionID, status.ApprovalID, "e30.e30.AA")
		result <- err
	}()
	if frame := readEnvelope(t, fixture.host); frame.Type != "approval.details.get" {
		t.Fatalf("RPC never started: %+v", frame)
	}
	cancel()
	if err := <-result; err == nil {
		t.Fatal("cancelled detail lookup accepted decision")
	}
	fixture.server.approvals.mu.Lock()
	pending := len(fixture.server.approvals.requests)
	fixture.server.approvals.mu.Unlock()
	if pending != 0 || fixture.stub.decisions != 0 {
		t.Fatal("cancelled lookup retained RPC or consumed signature")
	}
	principal := fixture.principal
	principal.ProofKeyJKT = "another-key"
	if _, _, err := fixture.server.DecideApproval(t.Context(), principal, fixture.repo.ticket.DeviceID, fixture.connectionID, status.ApprovalID, "e30.e30.AA"); !errors.Is(err, store.ErrAccessDenied) {
		t.Fatalf("another proof key took over admitted socket: %v", err)
	}
}

func TestApprovalSnapshotQueuesRacingReferencesAfterItsInitialCut(t *testing.T) {
	fixture := newApprovalRelayFixture(t, true)
	status := fixture.register(t)
	entered, release := make(chan struct{}), make(chan struct{})
	fixture.stub.mu.Lock()
	fixture.stub.snapshotHook = func() {
		close(entered)
		select {
		case <-release:
		case <-t.Context().Done():
		}
	}
	fixture.stub.mu.Unlock()
	writeWireFrame(t, fixture.device, map[string]any{"v": 1, "type": "approval.subscribe", "request_id": fixture.request.ApprovalID, "runtime_id": fixture.request.RuntimeID, "payload": map[string]any{}})
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("snapshot authorization did not start")
	}
	fixture.stub.mu.Lock()
	status.State = "denied"
	fixture.stub.statuses[status.ApprovalID] = status
	fixture.stub.mu.Unlock()
	fixture.server.approvals.publish(t.Context(), status.RuntimeID, status.ApprovalID)
	close(release)
	if snapshot := readEnvelope(t, fixture.device); snapshot.Type != "approval.snapshot" {
		t.Fatalf("reference overtook snapshot: %+v", snapshot)
	}
	update := readEnvelope(t, fixture.device)
	if update.Type != "approval.reference" || update.Payload["status"].(map[string]any)["state"] != "denied" {
		t.Fatalf("racing terminal state lost: %+v", update)
	}
}

func TestApprovalFragmentsRejectChangedRoutesAndOversizedOrUnsolicitedBodies(t *testing.T) {
	fixture := newApprovalRelayFixture(t, true)
	large := fixture.request
	large.Arguments = json.RawMessage(`{"command":"` + strings.Repeat("中文🙂", 10000) + `"}`)
	raw, _ := json.Marshal(large)
	binding, err := approval.ContextBinding(raw)
	if err != nil {
		t.Fatal(err)
	}
	status := store.ApprovalStatus{RuntimeID: large.RuntimeID, RuntimeEpoch: large.RuntimeEpoch, SessionID: large.SessionID}
	frames, err := encodeApprovalContext("approval.request", large.ApprovalID, status, binding.Canonical)
	if err != nil || len(frames) < 2 {
		t.Fatalf("large context not fragmented: %v", err)
	}
	for _, frame := range frames {
		writeWireFrame(t, fixture.host, frame)
	}
	if ack := readEnvelope(t, fixture.host); ack.Type != "approval.registered" {
		t.Fatalf("Unicode fragments did not reassemble: %+v", ack)
	}
	frames, err = encodeApprovalContext("approval.details", large.ExecutionID, status, binding.Canonical)
	if err != nil {
		t.Fatal(err)
	}
	writeWireFrame(t, fixture.host, frames[0])
	if frame := readEnvelope(t, fixture.host); frame.Type != "error" {
		t.Fatal("unsolicited detail body occupied assembly quota")
	}
	frames, err = encodeApprovalContext("approval.request", large.ExecutionID, status, binding.Canonical)
	if err != nil {
		t.Fatal(err)
	}
	writeWireFrame(t, fixture.host, frames[0])
	frames[1]["session_id"] = large.HostID
	writeWireFrame(t, fixture.host, frames[1])
	if frame := readEnvelope(t, fixture.host); frame.Type != "error" {
		t.Fatal("cross-session fragments stitched together")
	}
	fixture.server.approvals.mu.Lock()
	buffered := fixture.server.approvals.fragmentBytes
	fixture.server.approvals.mu.Unlock()
	if buffered != 0 {
		t.Fatal("invalid assembly retained private context bytes")
	}
}

func TestApprovalDrainCancelsSubscriptionWorkersAndOutstandingDetailRequests(t *testing.T) {
	fixture := newApprovalRelayFixture(t, true)
	status := fixture.register(t)
	writeWireFrame(t, fixture.device, map[string]any{"v": 1, "type": "approval.subscribe", "request_id": status.ApprovalID, "runtime_id": status.RuntimeID, "payload": map[string]any{}})
	if frame := readEnvelope(t, fixture.device); frame.Type != "approval.snapshot" {
		t.Fatalf("watch did not start: %+v", frame)
	}
	result := make(chan error, 1)
	go func() {
		_, _, err := fixture.server.DecideApproval(t.Context(), fixture.principal, fixture.repo.ticket.DeviceID, fixture.connectionID, status.ApprovalID, "e30.e30.AA")
		result <- err
	}()
	if frame := readEnvelope(t, fixture.host); frame.Type != "approval.details.get" {
		t.Fatalf("lookup did not start: %+v", frame)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := fixture.server.Drain(ctx); err != nil {
		t.Fatalf("approval drain left a live worker: %v", err)
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("drained lookup approved")
		}
	case <-ctx.Done():
		t.Fatal("drained detail lookup never settled")
	}
	fixture.server.approvals.mu.Lock()
	watches, requests, bytes := len(fixture.server.approvals.watchers), len(fixture.server.approvals.requests), fixture.server.approvals.fragmentBytes
	fixture.server.approvals.mu.Unlock()
	if watches != 0 || requests != 0 || bytes != 0 {
		t.Fatalf("drain retained approval work: watches=%d RPCs=%d bytes=%d", watches, requests, bytes)
	}
}

func TestApprovalStatusReconciliationNeedsNoOnlineHostOrBodyCache(t *testing.T) {
	fixture := newApprovalRelayFixture(t, true)
	status := fixture.register(t)
	fixture.stub.mu.Lock()
	status.State = "outcome_unknown"
	fixture.stub.statuses[status.ApprovalID] = status
	fixture.stub.mu.Unlock()
	_ = fixture.host.CloseNow()
	select {
	case <-fixture.repo.detached:
	case <-time.After(time.Second):
		t.Fatal("host did not detach")
	}
	writeWireFrame(t, fixture.device, map[string]any{"v": 1, "type": "approval.status.get", "request_id": status.ExecutionID, "runtime_id": status.RuntimeID, "payload": map[string]string{"approval_id": status.ApprovalID}})
	frame := readEnvelope(t, fixture.device)
	if frame.Type != "approval.reference" || frame.RequestID != status.ExecutionID || frame.Payload["status"].(map[string]any)["state"] != "outcome_unknown" {
		t.Fatalf("offline status lost authoritative result: %+v", frame)
	}
}

func TestApprovalWireRejectsCaseAliasesAndUnadvertisedEmptyRoutingFields(t *testing.T) {
	fixture := newApprovalRelayFixture(t, true)
	for _, variant := range []string{"Type", "runtime_epoch", "user_id", "payload_sha256"} {
		frame := map[string]any{"v": 1, "type": "approval.subscribe", "request_id": fixture.request.ApprovalID, "runtime_id": fixture.request.RuntimeID, "payload": map[string]any{}}
		if variant == "Type" {
			delete(frame, "type")
			frame["Type"] = "approval.subscribe"
		} else {
			frame[variant] = ""
		}
		writeWireFrame(t, fixture.device, frame)
		if response := readEnvelope(t, fixture.device); response.Type != "error" || response.Payload["code"] != "protocol.invalid" {
			t.Fatalf("non-contract envelope %s accepted: %+v", variant, response)
		}
	}
}

func TestApprovalResultDigestMatchesTypeScriptGolden(t *testing.T) {
	raw, err := os.ReadFile("../../../../contracts/ws/v1/approval-result.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden struct {
		Facts  json.RawMessage `json:"facts"`
		SHA256 string          `json:"sha256"`
	}
	if json.Unmarshal(raw, &golden) != nil {
		t.Fatal("invalid approval result golden")
	}
	var frame wireEnvelope
	if json.Unmarshal(golden.Facts, &frame) != nil {
		t.Fatal("invalid approval result facts")
	}
	if digest, err := approvalResultDigest(frame); err != nil || digest != golden.SHA256 {
		t.Fatalf("Go/TypeScript result digest differs: %s %v", digest, err)
	}
}

func TestApprovalInvalidationsTargetTheCurrentHostConnectionAndCarryOnlyActorMetadata(t *testing.T) {
	for _, topic := range []string{"approval.device.revoked", "runtime_grant.updated", "runtime_grant.revoked"} {
		t.Run(topic, func(t *testing.T) {
			fixture := newApprovalRelayFixture(t, true)
			other := store.ControlEvent{Topic: topic, RuntimeID: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", DeviceID: fixture.repo.ticket.DeviceID, UserID: fixture.repo.ticket.UserID, GrantVersion: 2}
			if err := fixture.server.ApplyControlEvent(t.Context(), other); err != nil {
				t.Fatal(err)
			}
			writeEnvelope(t, fixture.host, "ping", map[string]any{})
			if frame := readEnvelope(t, fixture.host); frame.Type != "pong" {
				t.Fatalf("another runtime's invalidation leaked: %+v", frame)
			}
			event := other
			event.RuntimeID = fixture.request.RuntimeID
			if err := fixture.server.ApplyControlEvent(t.Context(), event); err != nil {
				t.Fatal(err)
			}
			frame := readEnvelope(t, fixture.host)
			fixture.repo.mu.Lock()
			connectionID := fixture.repo.attached.ConnectionID
			fixture.repo.mu.Unlock()
			if frame.Type != "approval.invalidate" || frame.RuntimeEpoch != fixture.request.RuntimeEpoch || frame.Payload["connection_id"] != connectionID {
				t.Fatalf("host invalidation lost connection fence: %+v", frame)
			}
			if topic == "approval.device.revoked" {
				if frame.Payload["kind"] != "device.revoked" || frame.Payload["device_id"] != event.DeviceID {
					t.Fatalf("device invalidation: %+v", frame)
				}
			} else {
				if frame.Payload["kind"] != "grant.changed" || frame.Payload["user_id"] != event.UserID || frame.Payload["grant_version"] != float64(2) {
					t.Fatalf("grant invalidation: %+v", frame)
				}
			}
			if len(frame.Payload) != 3 && topic == "approval.device.revoked" {
				t.Fatal("device invalidation carried unrelated fields")
			}
			if len(frame.Payload) != 4 && topic != "approval.device.revoked" {
				t.Fatal("grant invalidation carried unrelated fields")
			}
		})
	}
}

func TestApprovalLegacyHostClosesWhenItCannotApplyScopedInvalidation(t *testing.T) {
	legacy := append([]string{}, supportedCapabilities...)
	legacy = append(legacy, approvalCapability)
	fixture := newApprovalRelayFixture(t, true, []string{"approval.decide", "session.read"}, legacy)
	if err := fixture.server.ApplyControlEvent(t.Context(), store.ControlEvent{Topic: "approval.device.revoked", RuntimeID: fixture.request.RuntimeID, DeviceID: fixture.repo.ticket.DeviceID}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, _, err := fixture.host.Read(ctx); err == nil {
		t.Fatal("legacy host kept cache authority after unsupported invalidation")
	}
}
