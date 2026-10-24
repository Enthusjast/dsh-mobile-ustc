package relay

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"dsh-mobile-ustc/services/remote/internal/approval"
	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/canonical"
	"dsh-mobile-ustc/services/remote/internal/store"
)

const approvalCapability = "approval.signed.v1"
const approvalInvalidationCapability = "approval.invalidation.v1"
const approvalRPCTimeout = 3 * time.Second

type ApprovalRepository interface {
	Register(context.Context, store.RuntimeConnection, int64, []byte) (store.ApprovalStatus, error)
	Decide(context.Context, auth.Principal, store.TicketRedemption, []byte, string) (store.ApprovalStatus, error)
	AuthorizeView(context.Context, store.TicketRedemption, string) (store.ApprovalStatus, error)
	AuthorizeStatus(context.Context, store.TicketRedemption, string) (store.ApprovalStatus, error)
	ListPending(context.Context, store.TicketRedemption) ([]store.ApprovalStatus, error)
	RecordResult(context.Context, store.RuntimeConnection, int64, store.ApprovalHostResult) (store.ApprovalStatus, error)
}
type ApprovalLeaseIssuer interface {
	Issue(context.Context, store.RuntimeConnection, int64, []byte) (string, error)
}
type ApprovalConfig struct {
	Control ApprovalRepository
	Leases  ApprovalLeaseIssuer
}

type approvalResponse struct {
	context []byte
	err     error
}
type approvalRPC struct {
	host, device *liveConnection
	status       store.ApprovalStatus
	response     chan approvalResponse
	answered     bool
}
type approvalRate struct {
	start time.Time
	count int
}
type approvalWatch struct {
	id      string
	ctx     context.Context
	cancel  context.CancelFunc
	pending map[string]struct{}
	wake    chan struct{}
}
type approvalRouter struct {
	server        *Server
	config        ApprovalConfig
	mu            sync.Mutex
	watchers      map[*liveConnection]*approvalWatch
	requests      map[string]*approvalRPC
	refs          map[*liveConnection]map[string]struct{}
	rates         map[*liveConnection]approvalRate
	fragments     map[string]*approvalAssembly
	fragmentBytes int
	workers       sync.WaitGroup
}

func newApprovalRouter(server *Server, config ApprovalConfig) *approvalRouter {
	return &approvalRouter{server: server, config: config, watchers: map[*liveConnection]*approvalWatch{}, requests: map[string]*approvalRPC{}, refs: map[*liveConnection]map[string]struct{}{}, rates: map[*liveConnection]approvalRate{}, fragments: map[string]*approvalAssembly{}}
}

func approvalConnection(host *liveConnection) store.RuntimeConnection {
	return store.RuntimeConnection{InstallationID: host.peer.installation.InstallationID, RuntimeID: host.runtimeID, RuntimeEpoch: host.runtimeEpoch, ConnectionID: host.connectionID, ProtocolVersion: 1}
}

func (router *approvalRouter) current(live *liveConnection) bool {
	router.server.mu.Lock()
	defer router.server.mu.Unlock()
	if live.closing || router.server.draining || router.server.connections[live.conn] != live {
		return false
	}
	return live.peer.role != "installation" || router.server.hosts[live.runtimeID] == live
}

func (router *approvalRouter) rate(live *liveConnection) bool {
	// Hold the server lock until the router lock is acquired so unregister cannot
	// delete this entry and then race a late admission into re-creating it.
	router.server.mu.Lock()
	if live.closing || router.server.draining || router.server.connections[live.conn] != live {
		router.server.mu.Unlock()
		return false
	}
	router.mu.Lock()
	router.server.mu.Unlock()
	defer router.mu.Unlock()
	now := time.Now()
	window := router.rates[live]
	if window.start.IsZero() || now.Sub(window.start) >= time.Second {
		window = approvalRate{start: now}
	}
	window.count++
	router.rates[live] = window
	return window.count <= 20
}

func (router *approvalRouter) route(ctx context.Context, live *liveConnection, host *store.RuntimeConnection, frame wireEnvelope) {
	if !router.current(live) {
		return
	}
	if !router.rate(live) {
		router.server.sendProtocolError(ctx, live, "rate.limited", &frame)
		return
	}
	if frame.RuntimeID != live.runtimeID || !uuidPattern.MatchString(frame.RequestID) || frame.DeviceID != "" || frame.UserID != "" || frame.SubscriptionID != "" || frame.SyncID != "" {
		router.server.sendProtocolError(ctx, live, "protocol.invalid", &frame)
		return
	}
	if frame.Type == "approval.subscribe" || frame.Type == "approval.unsubscribe" {
		router.watch(ctx, live, frame)
		return
	}
	if frame.Type == "approval.status.get" {
		var payload struct {
			ApprovalID string `json:"approval_id"`
		}
		if live.peer.role != "device" || frame.RuntimeEpoch != "" || frame.SessionID != "" || frame.PayloadSHA256 != "" || decodeApprovalPayload(frame.Payload, &payload, "approval_id") != nil || !uuidPattern.MatchString(payload.ApprovalID) {
			router.server.sendProtocolError(ctx, live, "protocol.invalid", &frame)
			return
		}
		status, err := router.config.Control.AuthorizeStatus(ctx, live.peer.redemption, payload.ApprovalID)
		if err != nil {
			router.server.sendProtocolError(ctx, live, approvalError(err), &frame)
			return
		}
		if router.current(live) {
			_ = live.sendJSON(ctx, approvalFrame("approval.reference", frame.RequestID, status, map[string]any{"status": status}))
		}
		return
	}
	if !uuidPattern.MatchString(frame.SessionID) || !uuidPattern.MatchString(frame.RuntimeEpoch) || (frame.Type != "approval.result" && frame.PayloadSHA256 != "") {
		router.server.sendProtocolError(ctx, live, "protocol.invalid", &frame)
		return
	}
	if frame.Type == "approval.details.get" {
		if live.peer.role != "device" {
			router.server.sendProtocolError(ctx, live, "access.denied", &frame)
			return
		}
		var payload struct {
			ApprovalID string `json:"approval_id"`
		}
		if decodeApprovalPayload(frame.Payload, &payload, "approval_id") != nil || !uuidPattern.MatchString(payload.ApprovalID) {
			router.server.sendProtocolError(ctx, live, "protocol.invalid", &frame)
			return
		}
		status, err := router.config.Control.AuthorizeView(ctx, live.peer.redemption, payload.ApprovalID)
		if err != nil {
			router.server.sendProtocolError(ctx, live, approvalError(err), &frame)
			return
		}
		if status.RuntimeEpoch != frame.RuntimeEpoch || status.SessionID != frame.SessionID {
			router.server.sendProtocolError(ctx, live, "approval.stale", &frame)
			return
		}
		raw, err := router.details(ctx, live, status)
		if err != nil {
			router.server.sendProtocolError(ctx, live, approvalError(err), &frame)
			return
		}
		frames, err := encodeApprovalContext("approval.details", frame.RequestID, status, raw)
		if err != nil {
			router.server.sendProtocolError(ctx, live, "protocol.frame_too_large", &frame)
			return
		}
		for _, outgoing := range frames {
			if _, err := router.config.Control.AuthorizeView(ctx, live.peer.redemption, status.ApprovalID); err != nil || !router.current(live) {
				return
			}
			if err := live.sendJSON(ctx, outgoing); err != nil {
				_ = live.conn.CloseNow()
				return
			}
		}
		return
	}
	if live.peer.role != "installation" || host == nil || !live.peer.installation.ExpiresAt.After(time.Now()) {
		router.server.sendProtocolError(ctx, live, "access.denied", &frame)
		return
	}
	if frame.Type != "approval.result" && frame.RuntimeEpoch != live.runtimeEpoch {
		router.server.sendProtocolError(ctx, live, "approval.stale", &frame)
		return
	}
	if frame.Type == "approval.fragment" {
		complete, err := router.fragment(live, frame)
		if err != nil {
			router.server.sendProtocolError(ctx, live, approvalError(err), &frame)
			return
		}
		if complete == nil {
			return
		}
		frame = *complete
	}
	switch frame.Type {
	case "approval.request", "approval.details":
		var payload struct {
			Context json.RawMessage `json:"context"`
		}
		if decodeApprovalPayload(frame.Payload, &payload, "context") != nil {
			router.server.sendProtocolError(ctx, live, "protocol.invalid", &frame)
			return
		}
		binding, err := approval.ContextBinding(payload.Context)
		if err != nil || binding.Context.RuntimeID != live.runtimeID || binding.Context.RuntimeEpoch != frame.RuntimeEpoch || binding.Context.SessionID != frame.SessionID {
			router.server.sendProtocolError(ctx, live, "protocol.invalid", &frame)
			return
		}
		if frame.Type == "approval.details" {
			router.respond(live, frame, binding)
			return
		}
		status, err := router.config.Control.Register(ctx, *host, live.peer.installation.KeyVersion, binding.Canonical)
		if err != nil {
			router.server.sendProtocolError(ctx, live, approvalError(err), &frame)
			return
		}
		router.mu.Lock()
		if router.refs[live] == nil {
			router.refs[live] = map[string]struct{}{}
		}
		if len(router.refs[live]) < 64 && (status.State == "pending" || status.State == "decision_received") {
			router.refs[live][status.ApprovalID] = struct{}{}
		}
		router.mu.Unlock()
		_ = live.sendJSON(ctx, approvalFrame("approval.registered", frame.RequestID, status, map[string]any{"status": status}))
		router.publish(ctx, status.RuntimeID, status.ApprovalID)
	case "approval.error":
		var payload struct {
			ApprovalID string `json:"approval_id"`
			Code       string `json:"code"`
		}
		if decodeApprovalPayload(frame.Payload, &payload, "approval_id", "code") != nil || (payload.Code != "approval.stale" && payload.Code != "approval.expired" && payload.Code != "internal") {
			router.server.sendProtocolError(ctx, live, "protocol.invalid", &frame)
			return
		}
		router.mu.Lock()
		pending := router.requests[frame.RequestID]
		if pending != nil && pending.host == live && pending.status.ApprovalID == payload.ApprovalID && pending.status.SessionID == frame.SessionID && pending.status.RuntimeEpoch == frame.RuntimeEpoch && !pending.answered {
			pending.answered = true
			pending.response <- approvalResponse{err: store.ErrApprovalExpired}
		}
		router.mu.Unlock()
	case "approval.result":
		router.result(ctx, live, *host, frame)
	default:
		router.server.sendProtocolError(ctx, live, "protocol.unsupported", &frame)
	}
}

func decodeApprovalPayload(raw []byte, target any, fields ...string) error {
	if err := decodePayload(raw, target); err != nil {
		return err
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil {
		return store.ErrApprovalInvalid
	}
	for name, value := range object {
		known := false
		for _, field := range fields {
			if name == field {
				known = true
				break
			}
		}
		if !known || string(value) == "null" {
			return store.ErrApprovalInvalid
		}
	}
	return nil
}

func exactApprovalEnvelope(raw []byte, kind string) bool {
	fields := map[string]bool{"v": true, "type": true, "request_id": true, "runtime_id": true, "payload": true}
	if kind != "approval.subscribe" && kind != "approval.unsubscribe" && kind != "approval.status.get" {
		fields["runtime_epoch"] = true
		fields["session_id"] = true
	}
	if kind == "approval.result" {
		fields["payload_sha256"] = true
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || len(object) != len(fields) {
		return false
	}
	for name, value := range object {
		if !fields[name] || string(value) == "null" {
			return false
		}
	}
	return true
}

func approvalError(err error) string {
	switch {
	case errors.Is(err, store.ErrApprovalConflict):
		return "approval.conflict"
	case errors.Is(err, store.ErrApprovalExpired):
		return "approval.expired"
	case errors.Is(err, store.ErrApprovalLimit):
		return "rate.limited"
	case errors.Is(err, store.ErrApprovalInvalid), errors.Is(err, approval.ErrContext), errors.Is(err, approval.ErrDecision):
		return "protocol.invalid"
	case errors.Is(err, auth.ErrAssurance):
		return "approval.assurance_required"
	}
	return commandErrorCode(err)
}

func approvalFrame(kind, requestID string, status store.ApprovalStatus, payload any) map[string]any {
	return map[string]any{"v": 1, "type": kind, "request_id": requestID, "runtime_id": status.RuntimeID, "runtime_epoch": status.RuntimeEpoch, "session_id": status.SessionID, "payload": payload}
}

func (router *approvalRouter) watch(ctx context.Context, live *liveConnection, frame wireEnvelope) {
	var payload struct{}
	if live.peer.role != "device" || frame.RuntimeEpoch != "" || frame.SessionID != "" || frame.PayloadSHA256 != "" || decodeApprovalPayload(frame.Payload, &payload) != nil {
		router.server.sendProtocolError(ctx, live, "protocol.invalid", &frame)
		return
	}
	if frame.Type == "approval.unsubscribe" {
		router.mu.Lock()
		if previous := router.watchers[live]; previous != nil {
			previous.cancel()
			delete(router.watchers, live)
		}
		router.mu.Unlock()
		_ = live.sendJSON(ctx, map[string]any{"v": 1, "type": "approval.unsubscribed", "request_id": frame.RequestID, "runtime_id": live.runtimeID, "payload": map[string]any{}})
		return
	}
	statuses, err := router.config.Control.ListPending(ctx, live.peer.redemption)
	if err != nil {
		router.server.sendProtocolError(ctx, live, approvalError(err), &frame)
		return
	}
	if len(statuses) > 64 {
		router.server.sendProtocolError(ctx, live, "internal", &frame)
		return
	}
	watchCtx, cancel := context.WithCancel(ctx)
	watch := &approvalWatch{id: frame.RequestID, ctx: watchCtx, cancel: cancel, pending: map[string]struct{}{}, wake: make(chan struct{}, 1)}
	router.mu.Lock()
	count := 0
	for watcher := range router.watchers {
		if watcher.runtimeID == live.runtimeID {
			count++
		}
	}
	previous := router.watchers[live]
	limited := previous == nil && (len(router.watchers) >= 16000 || count >= 64)
	if !limited {
		if previous != nil {
			previous.cancel()
		}
		router.watchers[live] = watch
	}
	router.mu.Unlock()
	if limited {
		cancel()
		router.server.sendProtocolError(ctx, live, "rate.limited", &frame)
		return
	}
	fail := func() {
		router.mu.Lock()
		if router.watchers[live] == watch {
			delete(router.watchers, live)
		}
		cancel()
		router.mu.Unlock()
	}
	// References queue while the snapshot is being built. Its single delivery
	// worker starts afterward and re-reads each changed ID under current scope.
	statuses, err = router.config.Control.ListPending(watchCtx, live.peer.redemption)
	if err != nil || len(statuses) > 64 {
		fail()
		router.server.sendProtocolError(ctx, live, approvalError(err), &frame)
		return
	}
	visible := []store.ApprovalStatus{}
	for _, status := range statuses {
		current, err := router.config.Control.AuthorizeStatus(watchCtx, live.peer.redemption, status.ApprovalID)
		if errors.Is(err, store.ErrAccessDenied) {
			continue
		}
		if err != nil {
			fail()
			router.server.sendProtocolError(ctx, live, approvalError(err), &frame)
			return
		}
		visible = append(visible, current)
	}
	if !router.current(live) {
		fail()
		return
	}
	if err := live.sendJSON(watchCtx, map[string]any{"v": 1, "type": "approval.snapshot", "request_id": frame.RequestID, "runtime_id": live.runtimeID, "payload": map[string]any{"items": visible}}); err != nil {
		fail()
		_ = live.conn.CloseNow()
		return
	}
	router.workers.Add(1)
	go func() { defer router.workers.Done(); router.deliverReferences(live, watch) }()
}

func (router *approvalRouter) publish(_ context.Context, runtimeID, approvalID string) {
	router.mu.Lock()
	overflow := []*liveConnection{}
	for live, watch := range router.watchers {
		if live.runtimeID != runtimeID {
			continue
		}
		if _, exists := watch.pending[approvalID]; !exists && len(watch.pending) >= 64 {
			delete(router.watchers, live)
			watch.cancel()
			overflow = append(overflow, live)
			continue
		}
		watch.pending[approvalID] = struct{}{}
		select {
		case watch.wake <- struct{}{}:
		default:
		}
	}
	router.mu.Unlock()
	for _, live := range overflow {
		_ = live.conn.CloseNow()
	}
}

func (router *approvalRouter) deliverReferences(live *liveConnection, watch *approvalWatch) {
	defer func() {
		router.mu.Lock()
		if router.watchers[live] == watch {
			delete(router.watchers, live)
		}
		watch.cancel()
		router.mu.Unlock()
	}()
	for {
		select {
		case <-watch.ctx.Done():
			return
		case <-live.done:
			return
		case <-watch.wake:
		}
		for {
			router.mu.Lock()
			id := ""
			if router.watchers[live] == watch {
				for pending := range watch.pending {
					id = pending
					delete(watch.pending, pending)
					break
				}
			}
			router.mu.Unlock()
			if id == "" {
				break
			}
			if !router.current(live) {
				return
			}
			status, err := router.config.Control.AuthorizeStatus(watch.ctx, live.peer.redemption, id)
			if errors.Is(err, store.ErrAccessDenied) {
				continue
			}
			if err != nil {
				_ = live.conn.CloseNow()
				return
			}
			if err := live.sendJSON(watch.ctx, approvalFrame("approval.reference", watch.id, status, map[string]any{"status": status})); err != nil {
				_ = live.conn.CloseNow()
				return
			}
		}
	}
}

func (router *approvalRouter) details(parent context.Context, device *liveConnection, status store.ApprovalStatus) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, approvalRPCTimeout)
	defer cancel()
	host := router.server.hostForRuntime(status.RuntimeID)
	if host == nil || !host.supports(approvalCapability) || host.runtimeEpoch != status.RuntimeEpoch || !host.peer.installation.ExpiresAt.After(time.Now()) {
		return nil, store.ErrRuntimeConnectionStale
	}
	id, err := randomUUID()
	if err != nil {
		return nil, store.ErrDatabaseUnavailable
	}
	pending := &approvalRPC{host: host, device: device, status: status, response: make(chan approvalResponse, 1)}
	router.mu.Lock()
	byHost, byDevice := 0, 0
	for _, active := range router.requests {
		if active.host == host {
			byHost++
		}
		if active.device == device {
			byDevice++
		}
	}
	if len(router.requests) >= 64 || byHost >= 8 || byDevice >= 4 {
		router.mu.Unlock()
		return nil, store.ErrApprovalLimit
	}
	router.requests[id] = pending
	router.mu.Unlock()
	defer func() {
		router.mu.Lock()
		delete(router.requests, id)
		router.dropFragmentLocked(host, id)
		router.mu.Unlock()
	}()
	if err := host.sendJSON(ctx, approvalFrame("approval.details.get", id, status, map[string]string{"approval_id": status.ApprovalID})); err != nil {
		return nil, store.ErrRuntimeConnectionStale
	}
	select {
	case response := <-pending.response:
		return response.context, response.err
	case <-ctx.Done():
		return nil, store.ErrDatabaseUnavailable
	case <-host.done:
		return nil, store.ErrRuntimeConnectionStale
	case <-device.done:
		return nil, store.ErrAccessDenied
	}
}

func (router *approvalRouter) respond(host *liveConnection, frame wireEnvelope, binding approval.Binding) {
	if !router.current(host) {
		return
	}
	router.mu.Lock()
	defer router.mu.Unlock()
	pending := router.requests[frame.RequestID]
	if pending == nil || pending.host != host || pending.answered {
		return
	}
	pending.answered = true
	if binding.Context.ApprovalID != pending.status.ApprovalID || binding.Context.SessionID != pending.status.SessionID || binding.Context.RuntimeEpoch != pending.status.RuntimeEpoch || binding.SHA256 != pending.status.BindingSHA256 {
		pending.response <- approvalResponse{err: store.ErrApprovalConflict}
		return
	}
	pending.response <- approvalResponse{context: binding.Canonical}
}

func (router *approvalRouter) result(ctx context.Context, live *liveConnection, host store.RuntimeConnection, frame wireEnvelope) {
	var payload struct {
		ApprovalID     string `json:"approval_id"`
		ExecutionID    string `json:"execution_id"`
		BindingSHA256  string `json:"binding_sha256"`
		DecisionSHA256 string `json:"decision_payload_sha256,omitempty"`
		State          string `json:"state"`
		Outcome        string `json:"execution_outcome,omitempty"`
	}
	if decodeApprovalPayload(frame.Payload, &payload, "approval_id", "execution_id", "binding_sha256", "decision_payload_sha256", "state", "execution_outcome") != nil {
		router.server.sendProtocolError(ctx, live, "protocol.invalid", &frame)
		return
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(frame.Payload, &fields)
	_, hasDecision := fields["decision_payload_sha256"]
	_, hasOutcome := fields["execution_outcome"]
	if (hasDecision && payload.DecisionSHA256 == "") || (hasOutcome && payload.Outcome == "") {
		router.server.sendProtocolError(ctx, live, "protocol.invalid", &frame)
		return
	}
	digest, err := approvalResultDigest(frame)
	if err != nil || frame.PayloadSHA256 != digest {
		router.server.sendProtocolError(ctx, live, "protocol.invalid", &frame)
		return
	}
	status, err := router.config.Control.RecordResult(ctx, host, live.peer.installation.KeyVersion, store.ApprovalHostResult{ApprovalID: payload.ApprovalID, SessionID: frame.SessionID, RuntimeEpoch: frame.RuntimeEpoch, ExecutionID: payload.ExecutionID, BindingSHA256: payload.BindingSHA256, DecisionPayloadSHA256: payload.DecisionSHA256, State: payload.State, Outcome: payload.Outcome})
	if err != nil {
		router.server.sendProtocolError(ctx, live, approvalError(err), &frame)
		return
	}
	if status.HostState == "settled" || status.State == "denied" || status.State == "expired" || status.State == "cancelled" || status.State == "invalidated" || status.State == "outcome_unknown" {
		router.mu.Lock()
		delete(router.refs[live], status.ApprovalID)
		router.mu.Unlock()
	}
	ack := approvalFrame("approval.result.ack", frame.RequestID, status, map[string]any{"status": status})
	ack["payload_sha256"] = digest
	_ = live.sendJSON(ctx, ack)
	router.publish(ctx, status.RuntimeID, status.ApprovalID)
}

func approvalResultDigest(frame wireEnvelope) (string, error) {
	raw, err := json.Marshal(map[string]any{"type": "approval.result", "runtime_id": frame.RuntimeID, "runtime_epoch": frame.RuntimeEpoch, "session_id": frame.SessionID, "payload": frame.Payload})
	if err != nil {
		return "", err
	}
	encoded, err := canonical.Object(raw)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

// DecideApproval is called only after fresh HTTP JWT/DPoP middleware. The phone
// references a live admitted socket; its narrower ticket remains authoritative.
func (server *Server) DecideApproval(ctx context.Context, principal auth.Principal, deviceID, connectionID, approvalID, decisionJWS string) (store.ApprovalStatus, string, error) {
	if server.approvals == nil {
		return store.ApprovalStatus{}, "", store.ErrApprovalInvalid
	}
	router := server.approvals
	server.mu.Lock()
	var device *liveConnection
	for _, candidate := range server.connections {
		if candidate.peer.role == "device" && candidate.connectionID == connectionID && candidate.peer.deviceID == deviceID && candidate.peer.redemption.ProofKeyThumbprint == principal.ProofKeyJKT && !candidate.closing && candidate.supports(approvalCapability) {
			device = candidate
			break
		}
	}
	server.mu.Unlock()
	if device == nil || !router.current(device) {
		return store.ApprovalStatus{}, "", store.ErrAccessDenied
	}
	if !router.rate(device) {
		return store.ApprovalStatus{}, "", store.ErrApprovalLimit
	}
	status, err := router.config.Control.AuthorizeView(ctx, device.peer.redemption, approvalID)
	if err != nil {
		return store.ApprovalStatus{}, "", err
	}
	raw, err := router.details(ctx, device, status)
	if err != nil {
		return store.ApprovalStatus{}, "", err
	}
	if !router.current(device) {
		return store.ApprovalStatus{}, "", store.ErrAccessDenied
	}
	status, err = router.config.Control.Decide(ctx, principal, device.peer.redemption, raw, decisionJWS)
	if err != nil {
		return store.ApprovalStatus{}, "", err
	}
	delivery := "pending"
	if status.State != "decision_received" && status.State != "denied" {
		return status, "recorded", nil
	}
	host := router.server.hostForRuntime(status.RuntimeID)
	if host != nil && host.supports(approvalCapability) && host.runtimeEpoch == status.RuntimeEpoch && router.current(host) {
		lease, issueErr := router.config.Leases.Issue(ctx, approvalConnection(host), host.peer.installation.KeyVersion, raw)
		if issueErr == nil {
			id, idErr := randomUUID()
			if idErr == nil && host.sendJSON(ctx, approvalFrame("approval.decision", id, status, map[string]string{"approval_id": approvalID, "decision_jws": decisionJWS, "authorization_jws": lease})) == nil {
				delivery = "forwarded"
			}
		}
	}
	router.publish(ctx, status.RuntimeID, status.ApprovalID)
	return status, delivery, nil
}

func (router *approvalRouter) closeConnection(live *liveConnection) {
	router.mu.Lock()
	if watch := router.watchers[live]; watch != nil {
		watch.cancel()
		delete(router.watchers, live)
	}
	delete(router.rates, live)
	ids := router.refs[live]
	delete(router.refs, live)
	for _, pending := range router.requests {
		if (pending.host == live || pending.device == live) && !pending.answered {
			pending.answered = true
			pending.response <- approvalResponse{err: store.ErrRuntimeConnectionStale}
		}
	}
	for key, fragment := range router.fragments {
		if fragment.host == live {
			router.dropAssemblyLocked(key, fragment)
		}
	}
	router.mu.Unlock()
	if live.peer.role == "installation" {
		ctx, cancel := context.WithTimeout(context.Background(), approvalRPCTimeout)
		defer cancel()
		for id := range ids {
			router.publish(ctx, live.runtimeID, id)
		}
	}
}
