package relay

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"time"
)

type sessionSubscription struct {
	id, requestID, sessionID, syncID string
	device, host                     *liveConnection
	ready                            bool
	pages                            map[string]string
	fragment                         *sessionFragmentState
	questions                        bool
	timedQuestions                   bool
	claims                           map[string]*questionClaim
	claimIDs                         map[string]struct{}
}

type sessionFragmentState struct {
	id, kind, requestID string
	count, next, bytes  int
}

type subscribePayload struct {
	MaxMessages *int `json:"max_messages"`
}
type pagePayload struct {
	SyncID      string `json:"sync_id"`
	ThroughSeq  *int64 `json:"through_seq"`
	BeforeSeq   *int64 `json:"before_seq"`
	MaxMessages *int   `json:"max_messages"`
}
type sessionFragmentPayload struct {
	Type  string `json:"type"`
	ID    string `json:"fragment_id"`
	Index *int   `json:"index"`
	Count *int   `json:"count"`
	Data  string `json:"data"`
}

func isSessionContent(kind string) bool {
	switch kind {
	case "session.snapshot", "session.event", "session.checkpoint", "assistant.start", "assistant.chunk", "assistant.end", "session.page.result", "question.snapshot", "question.timed.snapshot":
		return true
	}
	return false
}

func (server *Server) routeSessionRead(ctx context.Context, live *liveConnection, envelope wireEnvelope) {
	if !live.supports("session.read.v1") {
		server.sendProtocolError(ctx, live, "protocol.unsupported", &envelope)
		return
	}
	if envelope.RuntimeID != live.runtimeID || !uuidPattern.MatchString(envelope.RequestID) || !uuidPattern.MatchString(envelope.SessionID) ||
		envelope.UserID != "" || envelope.DeviceID != "" || envelope.PayloadSHA256 != "" || envelope.SyncID != "" {
		server.sendProtocolError(ctx, live, "protocol.invalid", &envelope)
		return
	}
	if envelope.Type != "session.subscribe" {
		server.routeExistingSessionRead(ctx, live, envelope)
		return
	}
	var payload subscribePayload
	if envelope.SubscriptionID != "" || envelope.RuntimeEpoch != "" || decodePayload(envelope.Payload, &payload) != nil ||
		(payload.MaxMessages != nil && (*payload.MaxMessages < 1 || *payload.MaxMessages > 100)) {
		server.sendProtocolError(ctx, live, "protocol.invalid", &envelope)
		return
	}
	if payload.MaxMessages == nil {
		value := 30
		payload.MaxMessages = &value
	}
	host := server.hostForRuntime(live.runtimeID)
	if host == nil || !host.peer.installation.ExpiresAt.After(time.Now()) {
		server.sendProtocolError(ctx, live, "runtime.offline", &envelope)
		return
	}
	if !host.supports("session.read.v1") {
		server.sendProtocolError(ctx, live, "protocol.unsupported", &envelope)
		return
	}
	if err := server.database.AuthorizeRealtimeSessionRead(ctx, live.peer.redemption, envelope.SessionID); err != nil {
		server.sendProtocolError(ctx, live, commandErrorCode(err), &envelope)
		return
	}
	if err := server.database.TouchRuntimeConnection(ctx, host.peer.installation.InstallationID, host.runtimeID, host.runtimeEpoch, host.connectionID); err != nil {
		server.sendProtocolError(ctx, live, "runtime.offline", &envelope)
		return
	}
	id, err := randomUUID()
	if err != nil {
		server.sendProtocolError(ctx, live, "internal", &envelope)
		return
	}
	subscription := &sessionSubscription{id: id, requestID: envelope.RequestID, sessionID: envelope.SessionID, device: live, host: host, pages: make(map[string]string), questions: live.supports("question.blocking.v1") && host.supports("question.blocking.v1")}
	subscription.timedQuestions = live.supports("question.timed.v1") && host.supports("question.timed.v1")
	subscription.claims = make(map[string]*questionClaim)
	subscription.claimIDs = make(map[string]struct{})
	server.mu.Lock()
	code := ""
	for _, existing := range live.subscriptions {
		if existing.requestID == envelope.RequestID {
			code = "command.request_conflict"
			break
		}
	}
	if code == "" && (len(live.subscriptions) >= 16 || len(host.subscriptions) >= 32 || len(server.subscriptions) >= 16_000) {
		code = "rate.limited"
	}
	if live.closing || host.closing || server.hosts[live.runtimeID] != host {
		code = "runtime.changed"
	}
	if code == "" {
		if live.subscriptions == nil {
			live.subscriptions = make(map[string]*sessionSubscription)
		}
		if host.subscriptions == nil {
			host.subscriptions = make(map[string]*sessionSubscription)
		}
		server.subscriptions[id] = subscription
		live.subscriptions[id], host.subscriptions[id] = subscription, subscription
	}
	server.mu.Unlock()
	if code != "" {
		server.sendProtocolError(ctx, live, code, &envelope)
		return
	}
	// Publish the route identity before the host can return its first snapshot.
	if err := live.sendJSON(ctx, server.subscriptionFrame(subscription, "session.subscribed", envelope.RequestID, map[string]any{})); err != nil {
		server.dropSubscription(ctx, subscription, "protocol.resync_required", false)
		return
	}
	envelope.SubscriptionID, envelope.RuntimeEpoch = id, host.runtimeEpoch
	forward := map[string]any{"max_messages": *payload.MaxMessages}
	if subscription.questions {
		forward["questions"] = true
	}
	if subscription.timedQuestions {
		forward["timed_questions"] = true
	}
	envelope.Payload, _ = json.Marshal(forward)
	if err := host.sendJSON(ctx, envelope); err != nil {
		server.dropSubscription(ctx, subscription, "protocol.resync_required", true)
	}
}

func (server *Server) routeExistingSessionRead(ctx context.Context, live *liveConnection, envelope wireEnvelope) {
	server.mu.Lock()
	subscription := server.subscriptions[envelope.SubscriptionID]
	owned := subscription != nil && subscription.device == live && subscription.sessionID == envelope.SessionID && envelope.RuntimeEpoch == subscription.host.runtimeEpoch
	server.mu.Unlock()
	if !owned {
		server.sendProtocolError(ctx, live, "protocol.resync_required", &envelope)
		return
	}
	if envelope.Type == "session.unsubscribe" {
		if decodePayload(envelope.Payload, &struct{}{}) != nil {
			server.sendProtocolError(ctx, live, "protocol.invalid", &envelope)
			return
		}
		server.dropSubscription(ctx, subscription, "", false)
		_ = live.sendJSON(ctx, server.subscriptionFrame(subscription, "session.unsubscribed", envelope.RequestID, map[string]any{}))
		return
	}
	var payload pagePayload
	if decodePayload(envelope.Payload, &payload) != nil || !uuidPattern.MatchString(payload.SyncID) || payload.ThroughSeq == nil || payload.BeforeSeq == nil ||
		*payload.ThroughSeq < -1 || *payload.ThroughSeq > 9_007_199_254_740_991 || *payload.BeforeSeq < 0 || *payload.BeforeSeq > *payload.ThroughSeq+1 ||
		(payload.MaxMessages != nil && (*payload.MaxMessages < 1 || *payload.MaxMessages > 100)) {
		server.sendProtocolError(ctx, live, "protocol.invalid", &envelope)
		return
	}
	if payload.MaxMessages == nil {
		value := 30
		payload.MaxMessages = &value
	}
	if err := server.database.AuthorizeRealtimeSessionRead(ctx, live.peer.redemption, envelope.SessionID); err != nil {
		server.dropSubscription(ctx, subscription, commandErrorCode(err), true)
		return
	}
	server.mu.Lock()
	code := ""
	if server.subscriptions[subscription.id] != subscription || !subscription.ready || subscription.syncID != payload.SyncID {
		code = "protocol.resync_required"
	} else if _, exists := subscription.pages[envelope.RequestID]; exists || len(subscription.pages) >= 4 || envelope.RequestID == subscription.requestID {
		code = "rate.limited"
	} else {
		subscription.pages[envelope.RequestID] = payload.SyncID
	}
	server.mu.Unlock()
	if code != "" {
		server.sendProtocolError(ctx, live, code, &envelope)
		return
	}
	envelope.Payload, _ = json.Marshal(payload)
	if err := subscription.host.sendJSON(ctx, envelope); err != nil {
		server.dropSubscription(ctx, subscription, "protocol.resync_required", true)
	}
}

func (server *Server) routeSessionContent(ctx context.Context, live *liveConnection, envelope wireEnvelope) {
	if !live.supports("session.read.v1") || envelope.RuntimeID != live.runtimeID || envelope.RuntimeEpoch != live.runtimeEpoch ||
		!uuidPattern.MatchString(envelope.SubscriptionID) || !uuidPattern.MatchString(envelope.RequestID) ||
		envelope.UserID != "" || envelope.DeviceID != "" || envelope.PayloadSHA256 != "" {
		server.sendProtocolError(ctx, live, "protocol.invalid", &envelope)
		return
	}
	server.mu.Lock()
	subscription := server.subscriptions[envelope.SubscriptionID]
	validHost := subscription != nil && !live.closing && !subscription.device.closing && subscription.host == live && server.hosts[live.runtimeID] == live && envelope.SessionID == subscription.sessionID
	server.mu.Unlock()
	if subscription == nil {
		// Frames already in flight after cancellation are discarded.
		return
	}
	if !validHost {
		server.sendProtocolError(ctx, live, "access.denied", &envelope)
		return
	}
	if err := server.database.TouchRuntimeConnection(ctx, live.peer.installation.InstallationID, live.runtimeID, live.runtimeEpoch, live.connectionID); err != nil {
		server.dropSubscription(ctx, subscription, "runtime.changed", true)
		return
	}
	if err := server.database.AuthorizeRealtimeSessionRead(ctx, subscription.device.peer.redemption, subscription.sessionID); err != nil {
		server.dropSubscription(ctx, subscription, commandErrorCode(err), true)
		return
	}
	server.mu.Lock()
	valid := !live.closing && !subscription.device.closing && server.subscriptions[subscription.id] == subscription && validateSessionContent(subscription, envelope)
	server.mu.Unlock()
	if !valid {
		server.dropSubscription(ctx, subscription, "protocol.resync_required", true)
		return
	}
	if err := subscription.device.sendJSON(ctx, envelope); err != nil {
		server.dropSubscription(ctx, subscription, "protocol.resync_required", false)
		_ = subscription.device.conn.CloseNow()
		return
	}
	if !envelope.receivedAt.IsZero() {
		server.metrics.RoutedSession(time.Since(envelope.receivedAt))
	}
	if (envelope.Type == "session.error" || envelope.Type == "session.closed") && envelope.RequestID == subscription.requestID {
		server.dropSubscription(ctx, subscription, "", false)
	}
}

// A fragmented payload is never reassembled or persisted by the Relay. Its
// route, sync identity, ordering and total byte budget are checked incrementally.
func validateSessionContent(subscription *sessionSubscription, envelope wireEnvelope) bool {
	kind := envelope.Type
	complete := true
	if kind == "session.error" || kind == "session.closed" {
		var payload struct {
			Code string `json:"code"`
		}
		if decodePayload(envelope.Payload, &payload) != nil || !sessionErrorCode(payload.Code) || envelope.SyncID != "" {
			return false
		}
		if envelope.RequestID != subscription.requestID {
			if kind != "session.error" || subscription.pages[envelope.RequestID] == "" {
				return false
			}
			delete(subscription.pages, envelope.RequestID)
		}
		return true
	}
	if !uuidPattern.MatchString(envelope.SyncID) {
		return false
	}
	if kind == "session.fragment" {
		var fragment sessionFragmentPayload
		if decodePayload(envelope.Payload, &fragment) != nil || !isSessionContent(fragment.Type) || !uuidPattern.MatchString(fragment.ID) ||
			fragment.Count == nil || fragment.Index == nil || *fragment.Count < 2 || *fragment.Count > 52 || *fragment.Index < 0 || *fragment.Index >= *fragment.Count {
			return false
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(fragment.Data)
		if err != nil || len(decoded) == 0 || len(decoded) > 40*1024 {
			return false
		}
		if *fragment.Index == 0 {
			if subscription.fragment != nil {
				return false
			}
			subscription.fragment = &sessionFragmentState{id: fragment.ID, kind: fragment.Type, requestID: envelope.RequestID, count: *fragment.Count}
		}
		state := subscription.fragment
		if state == nil || state.id != fragment.ID || state.kind != fragment.Type || state.requestID != envelope.RequestID || state.count != *fragment.Count || state.next != *fragment.Index {
			return false
		}
		state.next++
		state.bytes += len(decoded)
		if state.bytes > 2<<20 {
			return false
		}
		kind, complete = fragment.Type, state.next == state.count
		if complete {
			subscription.fragment = nil
		}
	} else if subscription.fragment != nil || !isSessionContent(kind) {
		return false
	}
	if kind == "session.snapshot" {
		if subscription.ready || envelope.RequestID != subscription.requestID || (subscription.syncID != "" && subscription.syncID != envelope.SyncID) {
			return false
		}
		subscription.syncID = envelope.SyncID
		if complete {
			subscription.ready = true
		}
		return true
	}
	if !subscription.ready || subscription.syncID != envelope.SyncID {
		return false
	}
	if kind == "question.snapshot" && !subscription.questions {
		return false
	}
	if kind == "question.timed.snapshot" && !subscription.timedQuestions {
		return false
	}
	if kind == "session.page.result" {
		if subscription.pages[envelope.RequestID] != envelope.SyncID {
			return false
		}
		if complete {
			delete(subscription.pages, envelope.RequestID)
		}
		return true
	}
	return envelope.RequestID == subscription.requestID
}

func sessionErrorCode(code string) bool {
	switch code {
	case "session.not_found", "runtime.changed", "access.denied", "protocol.snapshot_too_large", "protocol.resync_required", "rate.limited", "internal":
		return true
	}
	return false
}

func (server *Server) subscriptionFrame(subscription *sessionSubscription, kind, requestID string, payload any) map[string]any {
	return map[string]any{"v": 1, "type": kind, "request_id": requestID, "runtime_id": subscription.host.runtimeID, "runtime_epoch": subscription.host.runtimeEpoch,
		"session_id": subscription.sessionID, "subscription_id": subscription.id, "payload": payload}
}

func (server *Server) removeSubscriptionLocked(subscription *sessionSubscription) bool {
	if server.subscriptions[subscription.id] != subscription {
		return false
	}
	delete(server.subscriptions, subscription.id)
	delete(subscription.device.subscriptions, subscription.id)
	delete(subscription.host.subscriptions, subscription.id)
	return true
}

func (server *Server) dropSubscription(ctx context.Context, subscription *sessionSubscription, code string, notifyDevice bool) {
	server.mu.Lock()
	removed := server.removeSubscriptionLocked(subscription)
	server.mu.Unlock()
	if !removed {
		return
	}
	if code == "protocol.resync_required" {
		server.metrics.Resync()
	}
	writeCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	if notifyDevice {
		if err := subscription.device.sendJSON(writeCtx, server.subscriptionFrame(subscription, "session.error", subscription.requestID, map[string]string{"code": code})); err != nil {
			_ = subscription.device.conn.CloseNow()
		}
	}
	if err := subscription.host.sendJSON(writeCtx, server.subscriptionFrame(subscription, "session.unsubscribe", subscription.requestID, map[string]any{})); err != nil {
		// Without the cancellation frame the native follower could keep running;
		// disconnecting makes the host abort all followers on this transport.
		_ = subscription.host.conn.CloseNow()
	}
}

func (server *Server) closeConnectionSubscriptions(live *liveConnection) {
	server.mu.Lock()
	live.closing = true
	if server.hosts[live.runtimeID] == live {
		delete(server.hosts, live.runtimeID)
	}
	subscriptions := make([]*sessionSubscription, 0, len(live.subscriptions))
	for _, subscription := range live.subscriptions {
		server.removeSubscriptionLocked(subscription)
		subscriptions = append(subscriptions, subscription)
	}
	server.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	for _, subscription := range subscriptions {
		if subscription.host == live {
			if err := subscription.device.sendJSON(ctx, server.subscriptionFrame(subscription, "session.error", subscription.requestID, map[string]string{"code": "runtime.changed"})); err != nil {
				_ = subscription.device.conn.CloseNow()
			}
		} else {
			if err := subscription.host.sendJSON(ctx, server.subscriptionFrame(subscription, "session.unsubscribe", subscription.requestID, map[string]any{})); err != nil {
				_ = subscription.host.conn.CloseNow()
			}
		}
	}
}
