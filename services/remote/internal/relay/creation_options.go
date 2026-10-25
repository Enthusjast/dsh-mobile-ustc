package relay

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const creationOptionsCapability = "session.create_options.v1"
const maxCreationOptionsBytes = 16 * 1024 * 1024

type creationWorkspace struct {
	ID    string `json:"workspace_id"`
	Label string `json:"label"`
}
type sessionCreationOptions struct {
	Workspaces []creationWorkspace `json:"workspaces"`
	Presets    []string            `json:"presets"`
}

func validCreationOptions(options sessionCreationOptions) bool {
	if options.Workspaces == nil || options.Presets == nil || len(options.Workspaces) > 128 || len(options.Presets) > 128 {
		return false
	}
	seen := map[string]bool{}
	for _, item := range options.Workspaces {
		if !uuidPattern.MatchString(item.ID) || seen[item.ID] || strings.TrimSpace(item.Label) == "" || utf8.RuneCountInString(item.Label) > 32 || len(item.Label) > 128 {
			return false
		}
		for _, ch := range item.Label {
			if unicode.IsControl(ch) {
				return false
			}
		}
		seen[item.ID] = true
	}
	seen = map[string]bool{}
	for _, preset := range options.Presets {
		if !presetPattern.MatchString(preset) || seen[preset] {
			return false
		}
		seen[preset] = true
	}
	return true
}

func (server *Server) publishCreationOptions(ctx context.Context, live *liveConnection, envelope wireEnvelope) {
	if live.peer.role != "installation" || !live.supports(creationOptionsCapability) || !live.supports("session.create.v1") || !live.supports("command.relay.v1") {
		server.sendProtocolError(ctx, live, "protocol.unsupported", &envelope)
		return
	}
	if envelope.RuntimeID != live.runtimeID || envelope.RuntimeEpoch != live.runtimeEpoch || !uuidPattern.MatchString(envelope.RequestID) || envelope.SessionID != "" || envelope.DeviceID != "" || envelope.UserID != "" || envelope.PayloadSHA256 != "" || envelope.SubscriptionID != "" || envelope.SyncID != "" {
		server.sendProtocolError(ctx, live, "protocol.invalid", &envelope)
		return
	}
	var options sessionCreationOptions
	if decodePayload(envelope.Payload, &options) != nil || !validCreationOptions(options) {
		server.sendProtocolError(ctx, live, "protocol.invalid", &envelope)
		return
	}
	if !live.peer.installation.ExpiresAt.After(time.Now()) || server.database.TouchRuntimeConnection(ctx, live.peer.installation.InstallationID, live.runtimeID, live.runtimeEpoch, live.connectionID) != nil {
		server.sendProtocolError(ctx, live, "runtime.offline", &envelope)
		return
	}
	encoded, _ := json.Marshal(options)
	server.mu.Lock()
	current := server.hosts[live.runtimeID] == live && !live.closing
	bounded := server.creationOptionsBytes-live.creationOptionsBytes+len(encoded) <= maxCreationOptionsBytes
	if current && bounded {
		server.creationOptionsBytes += len(encoded) - live.creationOptionsBytes
		live.creationOptionsBytes = len(encoded)
		live.creationOptions = &options
	}
	server.mu.Unlock()
	if !current {
		server.sendProtocolError(ctx, live, "runtime.changed", &envelope)
		return
	}
	if !bounded {
		server.sendProtocolError(ctx, live, "rate.limited", &envelope)
		return
	}
	_ = live.sendJSON(ctx, map[string]any{"v": 1, "type": "session.create.options.ack", "request_id": envelope.RequestID, "runtime_id": live.runtimeID, "runtime_epoch": live.runtimeEpoch, "payload": map[string]any{"workspace_count": len(options.Workspaces), "preset_count": len(options.Presets), "server_time": time.Now().UTC()}})
}

func (server *Server) readCreationOptions(ctx context.Context, live *liveConnection, envelope wireEnvelope) {
	if !live.supports(creationOptionsCapability) || !live.supports("session.create.v1") || !live.supports("command.relay.v1") {
		server.sendProtocolError(ctx, live, "protocol.unsupported", &envelope)
		return
	}
	var empty struct{}
	if envelope.RuntimeID != live.runtimeID || !uuidPattern.MatchString(envelope.RequestID) || envelope.RuntimeEpoch != "" || envelope.SessionID != "" || envelope.DeviceID != "" || envelope.UserID != "" || envelope.PayloadSHA256 != "" || envelope.SubscriptionID != "" || envelope.SyncID != "" || decodePayload(envelope.Payload, &empty) != nil {
		server.sendProtocolError(ctx, live, "protocol.invalid", &envelope)
		return
	}
	if !slices.Contains(live.peer.redemption.Scope.Actions, "session.create") || len(live.peer.redemption.Scope.Workspaces) == 0 {
		server.sendProtocolError(ctx, live, "access.denied", &envelope)
		return
	}
	if err := server.database.ValidateRealtimeLease(ctx, live.peer.redemption); err != nil {
		server.revokeDeviceConnection(ctx, live, err)
		return
	}
	server.mu.Lock()
	host := server.hosts[live.runtimeID]
	var source *sessionCreationOptions
	if host != nil && !host.closing && host.supports(creationOptionsCapability) && host.peer.installation.ExpiresAt.After(time.Now()) {
		source = host.creationOptions
	}
	server.mu.Unlock()
	if host != nil && !host.supports(creationOptionsCapability) {
		server.sendProtocolError(ctx, live, "protocol.unsupported", &envelope)
		return
	}
	if source == nil {
		server.sendProtocolError(ctx, live, "runtime.offline", &envelope)
		return
	}
	if err := server.database.TouchRuntimeConnection(ctx, host.peer.installation.InstallationID, host.runtimeID, host.runtimeEpoch, host.connectionID); err != nil {
		server.sendProtocolError(ctx, live, "runtime.offline", &envelope)
		return
	}
	if err := server.database.ValidateRealtimeLease(ctx, live.peer.redemption); err != nil {
		server.revokeDeviceConnection(ctx, live, err)
		return
	}
	filtered := sessionCreationOptions{Workspaces: []creationWorkspace{}, Presets: []string{}}
	for _, item := range source.Workspaces {
		if slices.Contains(live.peer.redemption.Scope.Workspaces, item.ID) {
			filtered.Workspaces = append(filtered.Workspaces, item)
		}
	}
	if len(filtered.Workspaces) > 0 {
		filtered.Presets = append(filtered.Presets, source.Presets...)
	}
	server.mu.Lock()
	current := server.hosts[live.runtimeID] == host && !host.closing && !live.closing
	server.mu.Unlock()
	if !current {
		server.sendProtocolError(ctx, live, "runtime.changed", &envelope)
		return
	}
	_ = live.sendJSON(ctx, map[string]any{"v": 1, "type": "session.create.options.result", "request_id": envelope.RequestID, "runtime_id": live.runtimeID, "runtime_epoch": host.runtimeEpoch, "payload": filtered})
}
