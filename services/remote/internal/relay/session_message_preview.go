package relay

import (
	"context"
	"encoding/json"
	"strings"
	"unicode/utf8"
)

const messageActionsCapability = "session.message.actions.v1"

type messageForkAnchor struct {
	Version              int    `json:"v"`
	SubscriptionID       string `json:"subscription_id"`
	SyncID               string `json:"sync_id"`
	NativeSeq            *int64 `json:"native_seq"`
	MessageVersionSHA256 string `json:"message_version_sha256"`
	AnchorSHA256         string `json:"anchor_sha256"`
}

func validMessageForkAnchor(anchor messageForkAnchor) bool {
	return anchor.Version == 1 && uuidPattern.MatchString(anchor.SubscriptionID) && uuidPattern.MatchString(anchor.SyncID) && anchor.NativeSeq != nil && *anchor.NativeSeq >= 0 && *anchor.NativeSeq <= 9_007_199_254_740_991 && validSHA256Hex(anchor.MessageVersionSHA256) && validSHA256Hex(anchor.AnchorSHA256)
}
func (server *Server) routeMessagePreview(ctx context.Context, live *liveConnection, envelope wireEnvelope) {
	var syncID string
	if envelope.Type == "session.message.preview.get" {
		var request struct {
			SyncID    string `json:"sync_id"`
			NativeSeq *int64 `json:"native_seq"`
		}
		if decodePayload(envelope.Payload, &request) != nil || !exactReaderFields(envelope.Payload, "sync_id", "native_seq") || !uuidPattern.MatchString(request.SyncID) || request.NativeSeq == nil || *request.NativeSeq < 0 || *request.NativeSeq > 9_007_199_254_740_991 {
			server.sendProtocolError(ctx, live, "protocol.invalid", &envelope)
			return
		}
		syncID = request.SyncID
	} else if envelope.Type == "session.message.preview.confirm" {
		var request struct {
			SyncID string            `json:"sync_id"`
			Anchor messageForkAnchor `json:"anchor"`
		}
		if decodePayload(envelope.Payload, &request) != nil || !exactReaderFields(envelope.Payload, "sync_id", "anchor") || !validMessageForkAnchor(request.Anchor) || request.SyncID != request.Anchor.SyncID || request.Anchor.SubscriptionID != envelope.SubscriptionID {
			server.sendProtocolError(ctx, live, "protocol.invalid", &envelope)
			return
		}
		syncID = request.SyncID
	} else {
		server.sendProtocolError(ctx, live, "protocol.invalid", &envelope)
		return
	}
	server.routeReaderOperation(ctx, live, envelope, syncID, messageActionsCapability, "session.read", "session.message.preview.result", "session.message.preview.error", 1, "", "", 5_000)
}
func validMessagePreview(raw json.RawMessage, operation *readerOperation) bool {
	var page struct {
		Version   int               `json:"v"`
		Anchor    messageForkAnchor `json:"anchor"`
		Text      *string           `json:"text"`
		Shareable *bool             `json:"shareable"`
		Complete  *bool             `json:"complete"`
	}
	if len(raw) > 48*1024 || decodePayload(raw, &page) != nil || !exactReaderFields(raw, "v", "anchor", "text", "shareable", "complete") || page.Version != 1 || !validMessageForkAnchor(page.Anchor) || page.Anchor.SubscriptionID != operation.subscription.id || page.Anchor.SyncID != operation.syncID || page.Complete == nil || !*page.Complete || page.Shareable == nil || *page.Shareable != (page.Text != nil) || page.Text != nil && (len(*page.Text) == 0 || len(*page.Text) > 32*1024 || !utf8.ValidString(*page.Text)) {
		return false
	}
	if operation.requestType == "session.message.preview.get" {
		var request struct {
			SyncID    string `json:"sync_id"`
			NativeSeq *int64 `json:"native_seq"`
		}
		if decodePayload(operation.payload, &request) != nil || request.NativeSeq == nil || *request.NativeSeq != *page.Anchor.NativeSeq {
			return false
		}
	} else {
		var request struct {
			SyncID string            `json:"sync_id"`
			Anchor messageForkAnchor `json:"anchor"`
		}
		if decodePayload(operation.payload, &request) != nil || request.Anchor.NativeSeq == nil || *request.Anchor.NativeSeq != *page.Anchor.NativeSeq || request.Anchor.SubscriptionID != page.Anchor.SubscriptionID || request.Anchor.SyncID != page.Anchor.SyncID || request.Anchor.MessageVersionSHA256 != page.Anchor.MessageVersionSHA256 || request.Anchor.AnchorSHA256 != page.Anchor.AnchorSHA256 {
			return false
		}
	}
	if operation.requestType == "session.message.preview.confirm" && !*page.Shareable {
		return false
	}
	return page.Text == nil || strings.IndexFunc(*page.Text, func(ch rune) bool { return ch == 127 || ch < 32 && ch != '\n' && ch != '\r' && ch != '\t' }) < 0
}
func (server *Server) routeMessagePreviewResult(ctx context.Context, live *liveConnection, envelope wireEnvelope) {
	server.routeReaderOperationResult(ctx, live, envelope, validMessagePreview)
}
