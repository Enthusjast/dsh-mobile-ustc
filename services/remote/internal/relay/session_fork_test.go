package relay

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/store"
)

func (fake *relayTestStore) AuthorizeRealtimeSessionFork(ctx context.Context, ticket store.TicketRedemption, sourceID, workspaceID string) error {
	if err := fake.ValidateRealtimeLease(ctx, ticket); err != nil {
		return err
	}
	for _, action := range []string{"session.read", "session.fork", "session.create", "command.status"} {
		if !slices.Contains(ticket.Scope.Actions, action) {
			return store.ErrAccessDenied
		}
	}
	if !slices.Contains(ticket.Scope.Workspaces, workspaceID) || !slices.Contains(ticket.Scope.Sessions, sourceID) && len(ticket.Scope.Workspaces) == 0 {
		return store.ErrAccessDenied
	}
	return nil
}
func (fake *relayTestStore) RecordRealtimeSessionFork(ctx context.Context, ticket store.TicketRedemption, requestID, sourceID, workspaceID, digest string) (store.CommandStatus, error) {
	if err := fake.AuthorizeRealtimeSessionFork(ctx, ticket, sourceID, workspaceID); err != nil {
		return store.CommandStatus{}, err
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.commands == nil {
		fake.commands = make(map[string]store.CommandStatus)
	}
	if previous, ok := fake.commands[requestID]; ok {
		if previous.SessionID != sourceID || previous.WorkspaceID != workspaceID || previous.PayloadSHA256 != digest || previous.CommandType != "session.fork" {
			return store.CommandStatus{}, store.ErrCommandConflict
		}
		return previous, nil
	}
	status := store.CommandStatus{RequestID: requestID, SessionID: sourceID, WorkspaceID: workspaceID, CommandType: "session.fork", State: "received", PayloadSHA256: digest, UpdatedAt: time.Now()}
	fake.commands[requestID] = status
	return status, nil
}

func TestForkAnchorAndDigestBindPersistedBoundary(t *testing.T) {
	seq := int64(7)
	payload := sessionForkPayload{WorkspaceID: "88888888-8888-4888-8888-888888888888", Anchor: messageForkAnchor{Version: 1, SubscriptionID: "77777777-7777-4777-8777-777777777777", SyncID: "99999999-9999-4999-8999-999999999999", NativeSeq: &seq, MessageVersionSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", AnchorSHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}
	if !validMessageForkAnchor(payload.Anchor) {
		t.Fatal("valid persisted anchor rejected")
	}
	first, err := sessionForkDigest("55555555-5555-4555-8555-555555555555", "44444444-4444-4444-8444-444444444444", payload)
	if err != nil {
		t.Fatal(err)
	}
	seq = 8
	second, err := sessionForkDigest("55555555-5555-4555-8555-555555555555", "44444444-4444-4444-8444-444444444444", payload)
	if err != nil || first == second {
		t.Fatal("digest did not bind inclusive native seq")
	}
	payload.Anchor.NativeSeq = nil
	if validMessageForkAnchor(payload.Anchor) {
		t.Fatal("missing seq accepted as zero")
	}
	payload.Anchor.NativeSeq = &seq
	payload.Anchor.Version = 2
	if validMessageForkAnchor(payload.Anchor) {
		t.Fatal("unknown anchor version accepted")
	}
}
func TestMessagePreviewRejectsDifferentSelectedMessageAndExtraFields(t *testing.T) {
	seq := int64(7)
	anchor := messageForkAnchor{Version: 1, SubscriptionID: "77777777-7777-4777-8777-777777777777", SyncID: "99999999-9999-4999-8999-999999999999", NativeSeq: &seq, MessageVersionSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", AnchorSHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	request, _ := json.Marshal(map[string]any{"sync_id": anchor.SyncID, "native_seq": seq})
	op := &readerOperation{subscription: &sessionSubscription{id: anchor.SubscriptionID}, syncID: anchor.SyncID, requestType: "session.message.preview.get", payload: request}
	result := map[string]any{"v": 1, "anchor": anchor, "text": "explicit visible message", "shareable": true, "complete": true}
	raw, _ := json.Marshal(result)
	if !validMessagePreview(raw, op) {
		t.Fatal("exact preview rejected")
	}
	result["text"], result["shareable"] = nil, false
	raw, _ = json.Marshal(result)
	if !validMessagePreview(raw, op) {
		t.Fatal("attachment-only persisted anchor rejected")
	}
	result["shareable"] = true
	raw, _ = json.Marshal(result)
	if validMessagePreview(raw, op) {
		t.Fatal("null text falsely shareable")
	}
	result["text"], result["shareable"] = "explicit visible message", true
	seq = 8
	raw, _ = json.Marshal(result)
	if validMessagePreview(raw, op) {
		t.Fatal("preview for different native seq accepted")
	}
	seq = 7
	result["reasoning"] = "hidden"
	raw, _ = json.Marshal(result)
	if validMessagePreview(raw, op) {
		t.Fatal("extra hidden fields accepted")
	}
}
