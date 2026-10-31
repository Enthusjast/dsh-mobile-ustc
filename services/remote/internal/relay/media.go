package relay

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"time"

	"dsh-mobile-ustc/services/remote/internal/files"
)

const imageMessageCapability = "message.images.v1"
const sessionMediaCapability = "session.media.v1"
const maxImageBytes int64 = 16 * 1024 * 1024
const maxImagePixels int64 = 32_000_000
const maxImageDimension = 16_384

var mediaDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type mediaManifest struct {
	Name string `json:"name"`
	Size int64  `json:"size_bytes"`
	SHA  string `json:"sha256"`
}

func (value *mediaManifest) UnmarshalJSON(raw []byte) error {
	type plain mediaManifest
	var parsed plain
	if !exportObject(raw, []string{"name", "size_bytes", "sha256"}) || decodePayload(raw, &parsed) != nil {
		return errors.New("invalid media manifest")
	}
	*value = mediaManifest(parsed)
	return nil
}

type mediaReference struct {
	Version      int           `json:"v"`
	Origin       string        `json:"origin"`
	Seq          int64         `json:"native_seq"`
	Index        int           `json:"part_index"`
	EventVersion string        `json:"event_version_sha256"`
	Manifest     mediaManifest `json:"manifest"`
	MediaType    string        `json:"media_type"`
	Width        int64         `json:"width"`
	Height       int64         `json:"height"`
}

func (value *mediaReference) UnmarshalJSON(raw []byte) error {
	type plain mediaReference
	var parsed plain
	if !exportObject(raw, []string{"v", "origin", "native_seq", "part_index", "event_version_sha256", "manifest", "media_type", "width", "height"}) || decodePayload(raw, &parsed) != nil {
		return errors.New("invalid media reference")
	}
	*value = mediaReference(parsed)
	return nil
}
func validMediaReference(value mediaReference, request, runtime, session string) bool {
	if value.Version != 1 || value.Origin != "session_attachment" || value.Seq < 0 || value.Seq > 9_007_199_254_740_991 || value.Index < 0 || value.Index > 4095 ||
		!mediaDigestPattern.MatchString(value.EventVersion) || value.Manifest.Size < 1 || value.Manifest.Size > maxImageBytes ||
		value.Width < 1 || value.Height < 1 || value.Width > maxImageDimension || value.Height > maxImageDimension || value.Width*value.Height > maxImagePixels ||
		!slices.Contains([]string{"image/png", "image/jpeg", "image/webp", "image/gif"}, value.MediaType) {
		return false
	}
	_, err := files.NormalizeRegistration(files.UploadRegistration{RequestID: request, RuntimeID: runtime, SessionID: session,
		Name: value.Manifest.Name, SizeBytes: value.Manifest.Size, SHA256: value.Manifest.SHA})
	return err == nil
}

type mediaResolvePayload struct {
	Sync      string         `json:"sync_id"`
	Reference mediaReference `json:"reference"`
}
type mediaRead struct {
	requestID    string
	syncID       string
	reference    mediaReference
	grantVersion int64
	keyVersion   int64
	expires      time.Time
	until        time.Time
	timer        *time.Timer
}

func mediaErrorAllowed(code string) bool {
	switch code {
	case "access.denied", "runtime.changed", "runtime.offline", "protocol.unsupported", "protocol.invalid", "protocol.resync_required", "rate.limited", "file.export_unavailable", "file.export_changed", "file.export_unsupported", "file.too_large", "file.unavailable", "file.state_changed", "session.persistence_unavailable":
		return true
	}
	return false
}
func (server *Server) mediaError(sub *sessionSubscription, read *mediaRead, code string) map[string]any {
	frame := server.subscriptionFrame(sub, "session.media.error", read.requestID, map[string]string{"code": code})
	frame["sync_id"] = read.syncID
	return frame
}

// A reference is display metadata, never download authorization. The existing export authorizer remains mandatory.
func (server *Server) routeMediaResolve(ctx context.Context, phone *liveConnection, frame wireEnvelope) {
	var payload mediaResolvePayload
	if phone.peer.role != "device" || frame.RuntimeID != phone.runtimeID || !uuidPattern.MatchString(frame.RequestID) || !uuidPattern.MatchString(frame.SubscriptionID) ||
		!uuidPattern.MatchString(frame.SessionID) || !uuidPattern.MatchString(frame.RuntimeEpoch) || frame.SyncID != "" || frame.UserID != "" || frame.DeviceID != "" || frame.PayloadSHA256 != "" ||
		!exportObject(frame.Payload, []string{"sync_id", "reference"}) || decodePayload(frame.Payload, &payload) != nil || !uuidPattern.MatchString(payload.Sync) ||
		!validMediaReference(payload.Reference, frame.RequestID, frame.RuntimeID, frame.SessionID) {
		server.sendProtocolError(ctx, phone, "protocol.invalid", &frame)
		return
	}
	server.mu.Lock()
	sub := server.subscriptions[frame.SubscriptionID]
	owned := sub != nil && sub.device == phone && sub.sessionID == frame.SessionID && sub.host.runtimeEpoch == frame.RuntimeEpoch && sub.ready && sub.syncID == payload.Sync
	server.mu.Unlock()
	if !owned {
		server.sendProtocolError(ctx, phone, "protocol.resync_required", &frame)
		return
	}
	if server.exports == nil || !sub.media || !phone.supports(sessionMediaCapability) || !sub.host.supports(sessionMediaCapability) ||
		!phone.supports(files.ExportCapability) || !sub.host.supports(files.ExportCapability) {
		server.sendProtocolError(ctx, phone, "protocol.unsupported", &frame)
		return
	}
	if !slices.Contains(phone.peer.redemption.Scope.Actions, "file.download") {
		server.sendProtocolError(ctx, phone, "access.denied", &frame)
		return
	}
	check, cancel := context.WithTimeout(ctx, 2*time.Second)
	access, err := server.exports.database.AuthorizeRealtimeExport(check, phone.peer.redemption, frame.SessionID)
	cancel()
	if err != nil {
		server.dropSubscription(ctx, sub, exportCode(err), true)
		return
	}
	if err := server.database.AuthorizeRealtimeSessionRead(ctx, phone.peer.redemption, frame.SessionID); err != nil {
		server.dropSubscription(ctx, sub, commandErrorCode(err), true)
		return
	}
	if err := server.database.TouchRuntimeConnection(ctx, sub.host.peer.installation.InstallationID, sub.host.runtimeID, sub.host.runtimeEpoch, sub.host.connectionID); err != nil {
		server.dropSubscription(ctx, sub, "runtime.changed", true)
		return
	}
	id, err := randomUUID()
	if err != nil {
		server.sendProtocolError(ctx, phone, "internal", &frame)
		return
	}
	expires := time.Now().Add(5 * time.Minute)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	if sub.host.peer.installation.ExpiresAt.Before(expires) {
		expires = sub.host.peer.installation.ExpiresAt
	}
	read := &mediaRead{requestID: frame.RequestID, syncID: payload.Sync, reference: payload.Reference, grantVersion: access.GrantVersion,
		keyVersion: access.DeviceKeyVersion, expires: expires, until: access.LeaseUntil}
	if expires.Before(read.until) {
		read.until = expires
	}
	server.mu.Lock()
	code := ""
	if server.subscriptions[sub.id] != sub || phone.closing || sub.host.closing || server.hosts[phone.runtimeID] != sub.host || !sub.ready || sub.syncID != payload.Sync {
		code = "protocol.resync_required"
	} else if len(sub.mediaReads) >= 2 {
		code = "rate.limited"
	} else if frame.RequestID == sub.requestID || sub.pages[frame.RequestID] != "" || !read.until.After(time.Now().Add(100*time.Millisecond)) {
		code = "protocol.invalid"
	}
	for _, pending := range sub.mediaReads {
		if pending.requestID == frame.RequestID {
			code = "command.request_conflict"
		}
	}
	if code == "" {
		if sub.mediaReads == nil {
			sub.mediaReads = make(map[string]*mediaRead)
		}
		sub.mediaReads[id] = read
		read.timer = time.AfterFunc(max(0, time.Until(read.until)-100*time.Millisecond), func() {
			server.mu.Lock()
			current := server.subscriptions[sub.id] == sub && sub.mediaReads[id] == read
			if current {
				delete(sub.mediaReads, id)
			}
			server.mu.Unlock()
			if current {
				send, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
				defer cancel()
				_ = phone.sendJSON(send, server.mediaError(sub, read, "runtime.offline"))
			}
		})
	}
	server.mu.Unlock()
	if code != "" {
		server.sendProtocolError(ctx, phone, code, &frame)
		return
	}
	frame.RequestID = id
	frame.Payload, _ = json.Marshal(map[string]any{"sync_id": payload.Sync, "reference": payload.Reference, "user_id": access.UserID,
		"device_id": phone.peer.deviceID, "key_version": access.DeviceKeyVersion, "grant_version": access.GrantVersion,
		"allow_workspace": false, "lease_until": read.until, "expires_at": expires})
	if err := sub.host.sendJSON(ctx, frame); err != nil {
		server.dropSubscription(ctx, sub, "runtime.changed", true)
	}
}

func (server *Server) routeMediaResult(ctx context.Context, host *liveConnection, frame wireEnvelope) {
	if host.peer.role != "installation" || frame.RuntimeID != host.runtimeID || frame.RuntimeEpoch != host.runtimeEpoch || frame.UserID != "" || frame.DeviceID != "" || frame.PayloadSHA256 != "" ||
		!uuidPattern.MatchString(frame.SubscriptionID) || !uuidPattern.MatchString(frame.RequestID) || !uuidPattern.MatchString(frame.SessionID) || !uuidPattern.MatchString(frame.SyncID) {
		server.sendProtocolError(ctx, host, "protocol.invalid", &frame)
		return
	}
	server.mu.Lock()
	sub := server.subscriptions[frame.SubscriptionID]
	var read *mediaRead
	if sub != nil {
		read = sub.mediaReads[frame.RequestID]
	}
	owned := read != nil && sub.host == host && !host.closing && !sub.device.closing && server.hosts[host.runtimeID] == host && sub.sessionID == frame.SessionID && sub.syncID == frame.SyncID && read.syncID == frame.SyncID && read.until.After(time.Now())
	server.mu.Unlock()
	if read == nil {
		return
	}
	if !owned {
		server.sendProtocolError(ctx, host, "access.denied", &frame)
		return
	}
	if server.exports == nil || !sub.media || !host.supports(sessionMediaCapability) || !host.supports(files.ExportCapability) || !slices.Contains(sub.device.peer.redemption.Scope.Actions, "file.download") {
		server.dropSubscription(ctx, sub, "access.denied", true)
		return
	}
	valid := false
	if frame.Type == "session.media.result" {
		var result struct {
			Reference mediaReference `json:"reference"`
			Source    exportNode     `json:"source"`
		}
		valid = exportObject(frame.Payload, []string{"reference", "source"}) && decodePayload(frame.Payload, &result) == nil && result.Reference == read.reference &&
			validMediaReference(result.Reference, read.requestID, host.runtimeID, sub.sessionID) && uuidPattern.MatchString(result.Source.ID) && result.Source.Kind == "file" && result.Source.Origin == "session_attachment" &&
			result.Source.Name == read.reference.Manifest.Name && result.Source.Size != nil && *result.Source.Size == read.reference.Manifest.Size && result.Source.Unavailable == "" && result.Source.Expires.After(time.Now()) && !result.Source.Expires.After(read.expires)
	} else if frame.Type == "session.media.error" {
		var result struct {
			Code string `json:"code"`
		}
		valid = exportObject(frame.Payload, []string{"code"}) && decodePayload(frame.Payload, &result) == nil && mediaErrorAllowed(result.Code)
	}
	if !valid {
		server.dropSubscription(ctx, sub, "protocol.resync_required", true)
		return
	}
	check, cancel := context.WithTimeout(ctx, 2*time.Second)
	access, err := server.exports.database.AuthorizeRealtimeExport(check, sub.device.peer.redemption, sub.sessionID)
	cancel()
	if err != nil || access.GrantVersion != read.grantVersion || access.DeviceKeyVersion != read.keyVersion {
		server.dropSubscription(ctx, sub, "access.denied", true)
		return
	}
	if err := server.database.AuthorizeRealtimeSessionRead(ctx, sub.device.peer.redemption, sub.sessionID); err != nil {
		server.dropSubscription(ctx, sub, commandErrorCode(err), true)
		return
	}
	if err := server.database.TouchRuntimeConnection(ctx, host.peer.installation.InstallationID, host.runtimeID, host.runtimeEpoch, host.connectionID); err != nil {
		server.dropSubscription(ctx, sub, "runtime.changed", true)
		return
	}
	server.mu.Lock()
	current := server.subscriptions[sub.id] == sub && sub.mediaReads[frame.RequestID] == read && !host.closing && !sub.device.closing && server.hosts[host.runtimeID] == host && sub.syncID == read.syncID && read.until.After(time.Now())
	if current {
		delete(sub.mediaReads, frame.RequestID)
		read.timer.Stop()
	}
	server.mu.Unlock()
	if !current {
		return
	}
	frame.RequestID = read.requestID
	if err := sub.device.sendJSON(ctx, frame); err != nil {
		server.dropSubscription(ctx, sub, "protocol.resync_required", false)
	}
}
