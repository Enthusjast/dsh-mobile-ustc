package relay

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"
	"unicode/utf16"
)

const modelCatalogCapability = "session.models.v1"
const maxModelPageBytes = 32 * 1024

type modelPageRequest struct {
	SyncID string  `json:"sync_id"`
	Limit  int     `json:"limit"`
	Cursor *string `json:"cursor,omitempty"`
}
type modelCatalogLabel struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}
type modelCatalogItem struct {
	Provider modelCatalogLabel   `json:"provider"`
	Model    modelCatalogLabel   `json:"model"`
	Efforts  []modelCatalogLabel `json:"reasoning_efforts"`
}
type modelCatalogPage struct {
	Items       []modelCatalogItem `json:"items"`
	NextCursor  *string            `json:"next_cursor"`
	Unavailable *int               `json:"unavailable_provider_count"`
}
type modelRead struct {
	requestID, syncID string
	limit             int
	timer             *time.Timer
}

func validModelText(value string, limit int) bool {
	return len(value) > 0 && len(utf16.Encode([]rune(value))) <= limit
}
func validModelLabel(value modelCatalogLabel, limit int) bool {
	return validModelText(value.ID, limit) && validModelText(value.Label, 256) && !strings.ContainsAny(value.Label, "\x7f") && strings.IndexFunc(value.Label, func(ch rune) bool { return ch < 32 }) < 0
}
func validModelPage(raw json.RawMessage, limit int) bool {
	var page modelCatalogPage
	if len(raw) > maxModelPageBytes || decodePayload(raw, &page) != nil || page.Items == nil || len(page.Items) > limit || page.Unavailable == nil || *page.Unavailable < 0 || *page.Unavailable > 128 {
		return false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields["next_cursor"] == nil {
		return false
	}
	if page.NextCursor != nil && (!validModelText(*page.NextCursor, 1024) || len(page.Items) == 0) {
		return false
	}
	encoded, _ := json.Marshal(page)
	if len(encoded) > maxModelPageBytes {
		return false
	}
	seen := map[[2]string]bool{}
	for _, item := range page.Items {
		pair := [2]string{item.Provider.ID, item.Model.ID}
		if !validModelLabel(item.Provider, 128) || !validModelLabel(item.Model, 128) || seen[pair] || item.Efforts == nil || len(item.Efforts) > 32 {
			return false
		}
		seen[pair] = true
		efforts := map[string]bool{}
		for _, effort := range item.Efforts {
			if !validModelLabel(effort, 64) || efforts[effort.ID] {
				return false
			}
			efforts[effort.ID] = true
		}
	}
	return true
}

func (server *Server) routeModelRead(ctx context.Context, live *liveConnection, envelope wireEnvelope) {
	var request modelPageRequest
	if decodePayload(envelope.Payload, &request) != nil || !uuidPattern.MatchString(request.SyncID) || request.Limit < 1 || request.Limit > 50 || request.Cursor != nil && !validModelText(*request.Cursor, 1024) {
		server.sendProtocolError(ctx, live, "protocol.invalid", &envelope)
		return
	}
	// Null is not a missing cursor in the request contract.
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(envelope.Payload, &fields)
	if fields["cursor"] != nil && request.Cursor == nil {
		server.sendProtocolError(ctx, live, "protocol.invalid", &envelope)
		return
	}
	server.mu.Lock()
	sub := server.subscriptions[envelope.SubscriptionID]
	owned := sub != nil && sub.device == live && sub.sessionID == envelope.SessionID && sub.host.runtimeEpoch == envelope.RuntimeEpoch
	server.mu.Unlock()
	if !owned {
		server.sendProtocolError(ctx, live, "protocol.resync_required", &envelope)
		return
	}
	if !live.supports(modelCatalogCapability) || !sub.host.supports(modelCatalogCapability) {
		server.sendProtocolError(ctx, live, "protocol.unsupported", &envelope)
		return
	}
	if !slices.Contains(live.peer.redemption.Scope.Actions, "session.model.select") {
		server.sendProtocolError(ctx, live, "access.denied", &envelope)
		return
	}
	if err := server.database.AuthorizeRealtimeSessionRead(ctx, live.peer.redemption, envelope.SessionID); err != nil {
		server.dropSubscription(ctx, sub, commandErrorCode(err), true)
		return
	}
	if err := server.database.TouchRuntimeConnection(ctx, sub.host.peer.installation.InstallationID, sub.host.runtimeID, sub.host.runtimeEpoch, sub.host.connectionID); err != nil {
		server.dropSubscription(ctx, sub, "runtime.changed", true)
		return
	}
	id, err := randomUUID()
	if err != nil {
		server.sendProtocolError(ctx, live, "internal", &envelope)
		return
	}
	read := &modelRead{requestID: envelope.RequestID, syncID: request.SyncID, limit: request.Limit}
	server.mu.Lock()
	code := ""
	if server.subscriptions[sub.id] != sub || live.closing || sub.host.closing || server.hosts[live.runtimeID] != sub.host || !sub.ready || sub.syncID != request.SyncID {
		code = "protocol.resync_required"
	} else if len(sub.models) >= 2 {
		code = "rate.limited"
	} else if envelope.RequestID == sub.requestID || sub.pages[envelope.RequestID] != "" {
		code = "command.request_conflict"
	}
	for _, pending := range sub.models {
		if pending.requestID == envelope.RequestID {
			code = "command.request_conflict"
		}
	}
	if code == "" {
		if sub.models == nil {
			sub.models = make(map[string]*modelRead)
		}
		sub.models[id] = read
		read.timer = time.AfterFunc(5*time.Second, func() {
			server.mu.Lock()
			current := server.subscriptions[sub.id] == sub && sub.models[id] == read
			if current {
				delete(sub.models, id)
			}
			server.mu.Unlock()
			if current {
				send, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
				defer cancel()
				_ = live.sendJSON(send, server.modelError(sub, read, "runtime.offline"))
			}
		})
	}
	server.mu.Unlock()
	if code != "" {
		server.sendProtocolError(ctx, live, code, &envelope)
		return
	}
	envelope.RequestID = id
	if err := sub.host.sendJSON(ctx, envelope); err != nil {
		server.dropSubscription(ctx, sub, "runtime.changed", true)
	}
}

func (server *Server) modelError(sub *sessionSubscription, read *modelRead, code string) map[string]any {
	frame := server.subscriptionFrame(sub, "session.models.error", read.requestID, map[string]string{"code": code})
	frame["sync_id"] = read.syncID
	return frame
}

func (server *Server) routeModelResult(ctx context.Context, live *liveConnection, envelope wireEnvelope) {
	server.mu.Lock()
	sub := server.subscriptions[envelope.SubscriptionID]
	var read *modelRead
	if sub != nil {
		read = sub.models[envelope.RequestID]
	}
	owned := read != nil && sub.host == live && !live.closing && !sub.device.closing && server.hosts[live.runtimeID] == live && sub.sessionID == envelope.SessionID && sub.syncID == envelope.SyncID && read.syncID == envelope.SyncID
	server.mu.Unlock()
	if read == nil {
		return
	} // A timed-out or cancelled operation cannot claim a new route.
	if !owned {
		server.sendProtocolError(ctx, live, "access.denied", &envelope)
		return
	}
	valid := false
	if envelope.Type == "session.models.result" {
		valid = validModelPage(envelope.Payload, read.limit)
	} else {
		var result struct {
			Code string `json:"code"`
		}
		valid = decodePayload(envelope.Payload, &result) == nil && (sessionErrorCode(result.Code) || result.Code == "runtime.offline")
	}
	if !valid {
		server.dropSubscription(ctx, sub, "protocol.resync_required", true)
		return
	}
	if !slices.Contains(sub.device.peer.redemption.Scope.Actions, "session.model.select") {
		server.dropSubscription(ctx, sub, "access.denied", true)
		return
	}
	if err := server.database.AuthorizeRealtimeSessionRead(ctx, sub.device.peer.redemption, sub.sessionID); err != nil {
		server.dropSubscription(ctx, sub, commandErrorCode(err), true)
		return
	}
	if err := server.database.TouchRuntimeConnection(ctx, live.peer.installation.InstallationID, live.runtimeID, live.runtimeEpoch, live.connectionID); err != nil {
		server.dropSubscription(ctx, sub, "runtime.changed", true)
		return
	}
	server.mu.Lock()
	current := server.subscriptions[sub.id] == sub && sub.models[envelope.RequestID] == read && !live.closing && !sub.device.closing && server.hosts[live.runtimeID] == live
	if current {
		delete(sub.models, envelope.RequestID)
		read.timer.Stop()
	}
	server.mu.Unlock()
	if !current {
		return
	}
	envelope.RequestID = read.requestID
	if err := sub.device.sendJSON(ctx, envelope); err != nil {
		server.dropSubscription(ctx, sub, "protocol.resync_required", false)
	}
}
