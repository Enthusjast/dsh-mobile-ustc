package relay

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

const changesCapability = "session.changes.v1"

var changeOIDPattern = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
var changeModePattern = regexp.MustCompile(`^[0-7]{6}$`)

type readerOperation struct {
	subscription                                                              *sessionSubscription
	requestID, syncID, capability, action, resultType, errorType, requestType string
	limit                                                                     int
	snapshotID, fileID                                                        string
	payload                                                                   json.RawMessage
	timer                                                                     *time.Timer
}

func exactReaderFields(raw json.RawMessage, keys ...string) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, exists := fields[key]; !exists {
			return false
		}
	}
	return true
}

func (server *Server) routeChangesRead(ctx context.Context, live *liveConnection, envelope wireEnvelope) {
	if envelope.Type == "session.changes.get" {
		var request struct {
			SyncID string  `json:"sync_id"`
			Limit  *int    `json:"limit"`
			Cursor *string `json:"cursor,omitempty"`
		}
		if decodePayload(envelope.Payload, &request) != nil || !uuidPattern.MatchString(request.SyncID) || request.Limit == nil || *request.Limit < 1 || *request.Limit > 20 || request.Cursor != nil && !uuidPattern.MatchString(*request.Cursor) {
			server.sendProtocolError(ctx, live, "protocol.invalid", &envelope)
			return
		}
		keys := []string{"sync_id", "limit"}
		if request.Cursor != nil {
			keys = append(keys, "cursor")
		}
		if !exactReaderFields(envelope.Payload, keys...) {
			server.sendProtocolError(ctx, live, "protocol.invalid", &envelope)
			return
		}
		server.routeReaderOperation(ctx, live, envelope, request.SyncID, changesCapability, "session.changes.read", "session.changes.result", "session.changes.error", *request.Limit, "", "", 15_000)
	} else if envelope.Type == "session.changes.patch.get" {
		var request struct {
			SyncID     string  `json:"sync_id"`
			SnapshotID string  `json:"snapshot_id"`
			FileID     string  `json:"file_id"`
			Cursor     *string `json:"cursor,omitempty"`
		}
		if decodePayload(envelope.Payload, &request) != nil || !uuidPattern.MatchString(request.SyncID) || !uuidPattern.MatchString(request.SnapshotID) || !uuidPattern.MatchString(request.FileID) || request.Cursor != nil && !uuidPattern.MatchString(*request.Cursor) {
			server.sendProtocolError(ctx, live, "protocol.invalid", &envelope)
			return
		}
		keys := []string{"sync_id", "snapshot_id", "file_id"}
		if request.Cursor != nil {
			keys = append(keys, "cursor")
		}
		if !exactReaderFields(envelope.Payload, keys...) {
			server.sendProtocolError(ctx, live, "protocol.invalid", &envelope)
			return
		}
		server.routeReaderOperation(ctx, live, envelope, request.SyncID, changesCapability, "session.changes.read", "session.changes.patch.result", "session.changes.patch.error", 1, request.SnapshotID, request.FileID, 15_000)
	} else {
		server.sendProtocolError(ctx, live, "protocol.invalid", &envelope)
	}
}

func (server *Server) routeReaderOperation(ctx context.Context, live *liveConnection, envelope wireEnvelope, syncID, capability, action, resultType, errorType string, limit int, snapshotID, fileID string, timeoutMillis int) {
	if !live.supports("session.read.v1") || !live.supports(capability) {
		server.sendProtocolError(ctx, live, "protocol.unsupported", &envelope)
		return
	}
	if envelope.RuntimeID != live.runtimeID || !uuidPattern.MatchString(envelope.RequestID) || !uuidPattern.MatchString(envelope.SessionID) || !uuidPattern.MatchString(envelope.SubscriptionID) || !uuidPattern.MatchString(envelope.RuntimeEpoch) || envelope.SyncID != "" || envelope.UserID != "" || envelope.DeviceID != "" || envelope.PayloadSHA256 != "" || len(envelope.Payload) > 4096 {
		server.sendProtocolError(ctx, live, "protocol.invalid", &envelope)
		return
	}
	server.mu.Lock()
	sub := server.subscriptions[envelope.SubscriptionID]
	owned := sub != nil && sub.device == live && sub.sessionID == envelope.SessionID && sub.host.runtimeEpoch == envelope.RuntimeEpoch && sub.ready && sub.syncID == syncID
	server.mu.Unlock()
	if !owned {
		server.sendProtocolError(ctx, live, "protocol.resync_required", &envelope)
		return
	}
	if !sub.host.supports(capability) {
		server.sendProtocolError(ctx, live, "protocol.unsupported", &envelope)
		return
	}
	if !slices.Contains(live.peer.redemption.Scope.Actions, action) {
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
	op := &readerOperation{subscription: sub, requestID: envelope.RequestID, syncID: syncID, capability: capability, action: action, resultType: resultType, errorType: errorType, requestType: envelope.Type, limit: limit, snapshotID: snapshotID, fileID: fileID, payload: append(json.RawMessage(nil), envelope.Payload...)}
	server.mu.Lock()
	code := ""
	count := 0
	for _, old := range server.readerOperations {
		if old.subscription == sub {
			count++
			if old.requestID == op.requestID {
				code = "command.request_conflict"
			}
		}
	}
	if server.subscriptions[sub.id] != sub || live.closing || sub.host.closing || server.hosts[live.runtimeID] != sub.host || !sub.ready || sub.syncID != syncID {
		code = "protocol.resync_required"
	} else if count >= 2 || len(server.readerOperations) >= 32_000 {
		code = "rate.limited"
	} else if envelope.RequestID == sub.requestID || sub.pages[envelope.RequestID] != "" {
		code = "command.request_conflict"
	}
	if code == "" {
		if server.readerOperations == nil {
			server.readerOperations = make(map[string]*readerOperation)
		}
		server.readerOperations[id] = op
		op.timer = time.AfterFunc(time.Duration(timeoutMillis)*time.Millisecond, func() {
			server.mu.Lock()
			current := server.readerOperations[id] == op && server.subscriptions[sub.id] == sub
			if server.readerOperations[id] == op {
				delete(server.readerOperations, id)
			}
			server.mu.Unlock()
			if current {
				send, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
				defer cancel()
				frame := server.subscriptionFrame(sub, op.errorType, op.requestID, map[string]string{"code": "runtime.offline"})
				frame["sync_id"] = op.syncID
				_ = sub.device.sendJSON(send, frame)
			}
		})
	}
	server.mu.Unlock()
	if code != "" {
		server.sendProtocolError(ctx, live, code, &envelope)
		return
	}
	envelope.RequestID = id
	// Only Relay supplies current account/device facts; phone-provided owner fields were rejected above.
	if capability == messageActionsCapability {
		envelope.UserID, envelope.DeviceID = live.peer.redemption.UserID, live.peer.deviceID
	}
	if err := sub.host.sendJSON(ctx, envelope); err != nil {
		server.dropSubscription(ctx, sub, "runtime.changed", true)
	}
}

func (server *Server) removeReaderOperationsLocked(sub *sessionSubscription) {
	for id, op := range server.readerOperations {
		if op.subscription == sub {
			op.timer.Stop()
			delete(server.readerOperations, id)
		}
	}
}
func readerOperationError(code string) bool {
	switch code {
	case "session.not_found", "runtime.changed", "runtime.offline", "access.denied", "protocol.invalid", "protocol.snapshot_too_large", "protocol.resync_required", "rate.limited", "message.stale", "message.unavailable", "message.not_persisted", "changes.stale", "changes.unavailable", "changes.not_git", "changes.limit":
		return true
	}
	return false
}
func (server *Server) routeReaderOperationResult(ctx context.Context, live *liveConnection, envelope wireEnvelope, validate func(json.RawMessage, *readerOperation) bool) {
	server.mu.Lock()
	op := server.readerOperations[envelope.RequestID]
	owned := op != nil && op.subscription.host == live && server.subscriptions[op.subscription.id] == op.subscription && !live.closing && !op.subscription.device.closing && server.hosts[live.runtimeID] == live && op.subscription.sessionID == envelope.SessionID && op.subscription.id == envelope.SubscriptionID && op.subscription.syncID == envelope.SyncID && op.syncID == envelope.SyncID
	server.mu.Unlock()
	if op == nil {
		return
	}
	if !owned || envelope.RuntimeID != live.runtimeID || envelope.RuntimeEpoch != live.runtimeEpoch || envelope.UserID != "" || envelope.DeviceID != "" || envelope.PayloadSHA256 != "" {
		server.sendProtocolError(ctx, live, "access.denied", &envelope)
		return
	}
	valid := false
	if envelope.Type == op.resultType {
		valid = validate(envelope.Payload, op)
	} else if envelope.Type == op.errorType {
		var failure struct {
			Code string `json:"code"`
		}
		valid = len(envelope.Payload) <= 256 && decodePayload(envelope.Payload, &failure) == nil && readerOperationError(failure.Code)
	}
	if !valid {
		server.dropSubscription(ctx, op.subscription, "protocol.resync_required", true)
		return
	}
	if !slices.Contains(op.subscription.device.peer.redemption.Scope.Actions, op.action) {
		server.dropSubscription(ctx, op.subscription, "access.denied", true)
		return
	}
	if err := server.database.TouchRuntimeConnection(ctx, live.peer.installation.InstallationID, live.runtimeID, live.runtimeEpoch, live.connectionID); err != nil {
		server.dropSubscription(ctx, op.subscription, "runtime.changed", true)
		return
	}
	if err := server.database.AuthorizeRealtimeSessionRead(ctx, op.subscription.device.peer.redemption, op.subscription.sessionID); err != nil {
		server.dropSubscription(ctx, op.subscription, commandErrorCode(err), true)
		return
	}
	server.mu.Lock()
	current := server.readerOperations[envelope.RequestID] == op && server.subscriptions[op.subscription.id] == op.subscription && op.subscription.syncID == op.syncID
	if current {
		op.timer.Stop()
		delete(server.readerOperations, envelope.RequestID)
	}
	server.mu.Unlock()
	if !current {
		return
	}
	envelope.RequestID = op.requestID
	if err := op.subscription.device.sendJSON(ctx, envelope); err != nil {
		server.dropSubscription(ctx, op.subscription, "protocol.resync_required", false)
	}
}

type changesPath struct {
	Bytes   string `json:"bytes_base64"`
	Display string `json:"display"`
}

func validChangesPath(raw json.RawMessage) bool {
	if bytes.Equal(raw, []byte("null")) {
		return true
	}
	var path changesPath
	if decodePayload(raw, &path) != nil || !exactReaderFields(raw, "bytes_base64", "display") || len(path.Bytes) > 16_384 || len(path.Display) > 16_384 {
		return false
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(path.Bytes)
	return err == nil && len(decoded) > 0 && len(decoded) <= 4096 && !bytes.ContainsRune(decoded, 0) && base64.StdEncoding.EncodeToString(decoded) == path.Bytes && strings.IndexFunc(path.Display, func(ch rune) bool { return ch < 32 || ch > 126 }) < 0
}
func validChangesKind(kind string) bool {
	return kind == "text" || kind == "binary" || kind == "symlink" || kind == "gitlink"
}
func validChangesManifest(raw json.RawMessage, op *readerOperation) bool {
	var page struct {
		Version    int    `json:"v"`
		SyncID     string `json:"sync_id"`
		SnapshotID string `json:"snapshot_id"`
		Source     string `json:"source"`
		Base       struct {
			Kind string `json:"kind"`
			OID  string `json:"oid"`
		} `json:"base"`
		Digest         string            `json:"version"`
		ManifestSHA256 string            `json:"manifest_sha256"`
		ExpiresAt      string            `json:"expires_at"`
		Scope          string            `json:"scope"`
		Excluded       []string          `json:"excluded"`
		Complete       *bool             `json:"complete"`
		Truncated      *bool             `json:"truncated"`
		Files          []json.RawMessage `json:"files"`
		NextCursor     *string           `json:"next_cursor"`
	}
	if len(raw) > 32*1024 || decodePayload(raw, &page) != nil || !exactReaderFields(raw, "v", "sync_id", "snapshot_id", "source", "base", "version", "manifest_sha256", "expires_at", "scope", "excluded", "complete", "truncated", "files", "next_cursor") || page.Version != 1 || page.SyncID != op.syncID || !uuidPattern.MatchString(page.SnapshotID) || page.Source != "configured_workspace_git" || page.Base.Kind != "git_head" || !changeOIDPattern.MatchString(page.Base.OID) || !validSHA256Hex(page.Digest) || !validSHA256Hex(page.ManifestSHA256) || page.Scope != "tracked_head_to_index_worktree" || !slices.Equal(page.Excluded, []string{"untracked", "ignored", "submodule_contents"}) || page.Complete == nil || !*page.Complete || page.Truncated == nil || *page.Truncated || page.Files == nil || len(page.Files) > op.limit || page.NextCursor != nil && (!uuidPattern.MatchString(*page.NextCursor) || len(page.Files) == 0) {
		return false
	}
	expires, err := time.Parse(time.RFC3339Nano, page.ExpiresAt)
	if err != nil || !expires.After(time.Now()) || expires.After(time.Now().Add(31*time.Second)) {
		return false
	}
	seen := make(map[string]bool)
	for _, rawFile := range page.Files {
		var file struct {
			ID         string          `json:"file_id"`
			Status     string          `json:"status"`
			OldPath    json.RawMessage `json:"old_path"`
			NewPath    json.RawMessage `json:"new_path"`
			OldMode    string          `json:"old_mode"`
			NewMode    string          `json:"new_mode"`
			Kind       string          `json:"kind"`
			PatchBytes *int            `json:"patch_bytes"`
			Complete   *bool           `json:"complete"`
			Copyable   *bool           `json:"copyable"`
		}
		if decodePayload(rawFile, &file) != nil || !exactReaderFields(rawFile, "file_id", "status", "old_path", "new_path", "old_mode", "new_mode", "kind", "patch_bytes", "complete", "copyable") || !uuidPattern.MatchString(file.ID) || seen[file.ID] || !validChangesPath(file.OldPath) || !validChangesPath(file.NewPath) || !changeModePattern.MatchString(file.OldMode) || !changeModePattern.MatchString(file.NewMode) || !validChangesKind(file.Kind) || file.PatchBytes == nil || *file.PatchBytes < 0 || *file.PatchBytes > 1024*1024 || file.Complete == nil || file.Copyable == nil || *file.Copyable && (!*file.Complete || file.Kind == "binary") {
			return false
		}
		switch file.Status {
		case "added", "modified", "deleted", "renamed", "type_changed":
		default:
			return false
		}
		seen[file.ID] = true
	}
	return true
}
func validChangesPatch(raw json.RawMessage, op *readerOperation) bool {
	var page struct {
		Version     int               `json:"v"`
		SyncID      string            `json:"sync_id"`
		SnapshotID  string            `json:"snapshot_id"`
		FileID      string            `json:"file_id"`
		Digest      string            `json:"version"`
		Kind        string            `json:"kind"`
		Complete    *bool             `json:"complete"`
		Copyable    *bool             `json:"copyable"`
		Partial     *bool             `json:"partial"`
		PatchBase64 string            `json:"patch_base64"`
		PatchUTF8   *string           `json:"patch_utf8"`
		Hunks       []json.RawMessage `json:"hunks"`
		NextCursor  *string           `json:"next_cursor"`
	}
	if len(raw) > 16*1024 || decodePayload(raw, &page) != nil || !exactReaderFields(raw, "v", "sync_id", "snapshot_id", "file_id", "version", "kind", "complete", "copyable", "partial", "patch_base64", "patch_utf8", "hunks", "next_cursor") || page.Version != 1 || page.SyncID != op.syncID || page.SnapshotID != op.snapshotID || page.FileID != op.fileID || !validSHA256Hex(page.Digest) || !validChangesKind(page.Kind) || page.Complete == nil || page.Copyable == nil || page.Partial == nil || page.Hunks == nil || len(page.Hunks) > 20_000 || page.NextCursor != nil && !uuidPattern.MatchString(*page.NextCursor) {
		return false
	}
	patch, err := base64.StdEncoding.Strict().DecodeString(page.PatchBase64)
	if err != nil || base64.StdEncoding.EncodeToString(patch) != page.PatchBase64 {
		return false
	}
	if page.PatchUTF8 != nil && (!utf8.Valid(patch) || string(patch) != *page.PatchUTF8) {
		return false
	}
	if *page.Copyable && (!*page.Complete || *page.Partial || page.NextCursor != nil || page.PatchUTF8 == nil || page.Kind == "binary") {
		return false
	}
	lines := 0
	for _, rawHunk := range page.Hunks {
		var hunk struct {
			OldStart *int64            `json:"old_start"`
			OldCount *int64            `json:"old_count"`
			NewStart *int64            `json:"new_start"`
			NewCount *int64            `json:"new_count"`
			Lines    []json.RawMessage `json:"lines"`
		}
		if decodePayload(rawHunk, &hunk) != nil || !exactReaderFields(rawHunk, "old_start", "old_count", "new_start", "new_count", "lines") || hunk.OldStart == nil || hunk.OldCount == nil || hunk.NewStart == nil || hunk.NewCount == nil || *hunk.OldStart < 0 || *hunk.OldCount < 0 || *hunk.NewStart < 0 || *hunk.NewCount < 0 || hunk.Lines == nil {
			return false
		}
		for _, rawLine := range hunk.Lines {
			lines++
			if lines > 20_000 {
				return false
			}
			var line struct {
				Kind    string  `json:"kind"`
				Bytes   string  `json:"bytes_base64"`
				Text    *string `json:"text"`
				OldLine *int64  `json:"old_line"`
				NewLine *int64  `json:"new_line"`
			}
			if decodePayload(rawLine, &line) != nil || !exactReaderFields(rawLine, "kind", "bytes_base64", "text", "old_line", "new_line") || line.OldLine != nil && (*line.OldLine < 0 || *line.OldLine > 9_007_199_254_740_991) || line.NewLine != nil && (*line.NewLine < 0 || *line.NewLine > 9_007_199_254_740_991) {
				return false
			}
			switch line.Kind {
			case "context", "add", "delete", "no_final_newline":
			default:
				return false
			}
			decoded, err := base64.StdEncoding.Strict().DecodeString(line.Bytes)
			if err != nil || base64.StdEncoding.EncodeToString(decoded) != line.Bytes || line.Text != nil && (!utf8.Valid(decoded) || string(decoded) != *line.Text) {
				return false
			}
		}
	}
	return true
}
func (server *Server) routeChangesResult(ctx context.Context, live *liveConnection, envelope wireEnvelope) {
	server.routeReaderOperationResult(ctx, live, envelope, func(raw json.RawMessage, op *readerOperation) bool {
		if op.resultType == "session.changes.result" {
			return validChangesManifest(raw, op)
		}
		return validChangesPatch(raw, op)
	})
}
