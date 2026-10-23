package relay

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"time"
)

var presetPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type sessionCreatePayload struct {
	WorkspaceID string `json:"workspace_id"`
	Preset      string `json:"preset"`
}

func (server *Server) routeSessionCreate(ctx context.Context, live *liveConnection, envelope wireEnvelope) {
	if !live.supports("command.relay.v1") || !live.supports("session.create.v1") {
		server.sendProtocolError(ctx, live, "protocol.unsupported", &envelope)
		return
	}
	if !uuidPattern.MatchString(envelope.RequestID) || envelope.RuntimeID != live.runtimeID || !uuidPattern.MatchString(envelope.RuntimeEpoch) ||
		envelope.SessionID != "" || envelope.UserID != "" || envelope.DeviceID != "" || envelope.PayloadSHA256 != "" || envelope.SubscriptionID != "" || envelope.SyncID != "" {
		server.sendProtocolError(ctx, live, "protocol.invalid", &envelope)
		return
	}
	var payload sessionCreatePayload
	if decodePayload(envelope.Payload, &payload) != nil || !uuidPattern.MatchString(payload.WorkspaceID) || !presetPattern.MatchString(payload.Preset) {
		server.sendProtocolError(ctx, live, "protocol.invalid", &envelope)
		return
	}
	host := server.hostForRuntime(live.runtimeID)
	if host == nil || !host.peer.installation.ExpiresAt.After(time.Now()) {
		server.sendProtocolError(ctx, live, "runtime.offline", &envelope)
		return
	}
	if !host.supports("command.relay.v1") || !host.supports("session.create.v1") {
		server.sendProtocolError(ctx, live, "protocol.unsupported", &envelope)
		return
	}
	if host.runtimeEpoch != envelope.RuntimeEpoch {
		server.sendProtocolError(ctx, live, "runtime.changed", &envelope)
		return
	}
	check, cancel := context.WithTimeout(ctx, 3*time.Second)
	err := server.database.TouchRuntimeConnection(check, host.peer.installation.InstallationID, host.runtimeID, host.runtimeEpoch, host.connectionID)
	cancel()
	if err != nil {
		_ = host.conn.CloseNow()
		server.sendProtocolError(ctx, live, "runtime.offline", &envelope)
		return
	}
	digest := sessionCreateDigest(envelope.RuntimeEpoch, payload)
	status, err := server.database.RecordRealtimeSessionCreate(ctx, live.peer.redemption, envelope.RequestID, payload.WorkspaceID, digest)
	if err != nil {
		server.sendProtocolError(ctx, live, commandErrorCode(err), &envelope)
		return
	}
	server.forwardRecordedCommand(ctx, live, host, envelope, payload, digest, status)
}

func sessionCreateDigest(epoch string, payload sessionCreatePayload) string {
	// Preset names and UUIDs are ASCII tokens checked before digesting.
	encoded := `{"payload":{"preset":"` + payload.Preset + `","workspace_id":"` + payload.WorkspaceID + `"},"runtime_epoch":"` + epoch + `","type":"session.create"}`
	digest := sha256.Sum256([]byte(encoded))
	return hex.EncodeToString(digest[:])
}
