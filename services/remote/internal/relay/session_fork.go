package relay

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"dsh-mobile-ustc/services/remote/internal/canonical"
)

const sessionForkCapability = "session.fork.v1"

type sessionForkPayload struct {
	WorkspaceID string            `json:"workspace_id"`
	Anchor      messageForkAnchor `json:"anchor"`
}

func sessionForkDigest(sessionID, epoch string, payload sessionForkPayload) (string, error) {
	raw, err := json.Marshal(map[string]any{"type": "session.fork", "runtime_epoch": epoch, "session_id": sessionID, "payload": payload})
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

func (server *Server) routeSessionFork(ctx context.Context, live *liveConnection, envelope wireEnvelope) {
	if !live.supports("command.relay.v1") || !live.supports(sessionForkCapability) || !live.supports(messageActionsCapability) {
		server.sendProtocolError(ctx, live, "protocol.unsupported", &envelope)
		return
	}
	if !uuidPattern.MatchString(envelope.RequestID) || envelope.RuntimeID != live.runtimeID || !uuidPattern.MatchString(envelope.RuntimeEpoch) ||
		!uuidPattern.MatchString(envelope.SessionID) || envelope.UserID != "" || envelope.DeviceID != "" || envelope.PayloadSHA256 != "" || envelope.SubscriptionID != "" || envelope.SyncID != "" {
		server.sendProtocolError(ctx, live, "protocol.invalid", &envelope)
		return
	}
	var payload sessionForkPayload
	if decodePayload(envelope.Payload, &payload) != nil || !uuidPattern.MatchString(payload.WorkspaceID) || !validMessageForkAnchor(payload.Anchor) {
		server.sendProtocolError(ctx, live, "protocol.invalid", &envelope)
		return
	}
	host := server.hostForRuntime(live.runtimeID)
	if host == nil || !host.peer.installation.ExpiresAt.After(time.Now()) {
		server.sendProtocolError(ctx, live, "runtime.offline", &envelope)
		return
	}
	if !host.supports("command.relay.v1") || !host.supports(sessionForkCapability) || !host.supports(messageActionsCapability) {
		server.sendProtocolError(ctx, live, "protocol.unsupported", &envelope)
		return
	}
	if host.runtimeEpoch != envelope.RuntimeEpoch {
		server.sendProtocolError(ctx, live, "runtime.changed", &envelope)
		return
	}
	if err := server.database.TouchRuntimeConnection(ctx, host.peer.installation.InstallationID, host.runtimeID, host.runtimeEpoch, host.connectionID); err != nil {
		server.sendProtocolError(ctx, live, "runtime.offline", &envelope)
		return
	}
	digest, err := sessionForkDigest(envelope.SessionID, envelope.RuntimeEpoch, payload)
	if err != nil {
		server.sendProtocolError(ctx, live, "protocol.invalid", &envelope)
		return
	}
	status, err := server.database.RecordRealtimeSessionFork(ctx, live.peer.redemption, envelope.RequestID, envelope.SessionID, payload.WorkspaceID, digest)
	if err != nil {
		server.sendProtocolError(ctx, live, commandErrorCode(err), &envelope)
		return
	}
	if status.State == "received" {
		server.mu.Lock()
		sub := server.subscriptions[payload.Anchor.SubscriptionID]
		owned := sub != nil && sub.device == live && sub.host == host && sub.sessionID == envelope.SessionID && sub.ready && sub.syncID == payload.Anchor.SyncID && !live.closing && !host.closing
		server.mu.Unlock()
		if !owned {
			server.sendProtocolError(ctx, live, "message.stale", &envelope)
			return
		}
		// Admission and dispatch are separate authority boundaries; locks/time checks are repeated immediately before forwarding.
		if err := server.database.AuthorizeRealtimeSessionFork(ctx, live.peer.redemption, envelope.SessionID, payload.WorkspaceID); err != nil {
			server.sendProtocolError(ctx, live, commandErrorCode(err), &envelope)
			return
		}
	}
	server.forwardRecordedCommand(ctx, live, host, envelope, payload, digest, status)
}
