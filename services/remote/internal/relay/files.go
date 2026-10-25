package relay

import (
	"context"
	"sync"
	"time"

	"dsh-mobile-ustc/services/remote/internal/files"
	"dsh-mobile-ustc/services/remote/internal/store"
)

type fileMessageRecorder interface {
	RecordRealtimeFileCommand(context.Context, store.TicketRedemption, files.HostBinding, string, string, string, string, []string, func() bool) (store.CommandStatus, error)
}

func (server *Server) EnableFiles(controller *files.Handoffs) {
	server.fileHandoffs = controller
	server.fileMessages, _ = server.database.(fileMessageRecorder)
}

func (server *Server) FileHostLifetime(host files.HostBinding) (<-chan struct{}, error) {
	server.mu.Lock()
	defer server.mu.Unlock()
	live := server.hosts[host.RuntimeID]
	if server.fileHandoffs == nil || live == nil || live.closing || !live.supports(files.HandoffCapability) || !live.supports("session.catalog.v1") || live.runtimeEpoch != host.RuntimeEpoch || live.connectionID != host.ConnectionID ||
		live.peer.installation.InstallationID != host.InstallationID || live.peer.installation.KeyVersion != host.KeyVersion || !live.peer.installation.ExpiresAt.After(time.Now()) {
		return nil, files.ErrAccess
	}
	return live.done, nil
}

type fileRoute struct {
	file, session string
	until         time.Time
	staged        bool
}

func (server *Server) FileDeliveryHint(runtime, session, id string) *files.Delivery {
	waiting := &files.Delivery{State: "waiting"}
	server.mu.Lock()
	host := server.hosts[runtime]
	var peer *filePeer
	if host != nil && !host.closing && host.supports(files.MessageCapability) {
		peer = host.filePeer
	}
	server.mu.Unlock()
	if peer == nil || peer.ctx.Err() != nil {
		return waiting
	}
	peer.mu.Lock()
	defer peer.mu.Unlock()
	for _, route := range peer.active {
		if route.file == id && route.session == session && route.staged && route.until.After(time.Now().Add(100*time.Millisecond)) {
			until := route.until
			return &files.Delivery{State: "ready", ExpiresAt: &until}
		}
	}
	return waiting
}

// The stage ack must enter the Host socket queue before an attached command.
// Database staged alone can be visible just before that ack has been sent.
func (server *Server) filesReady(host *liveConnection, session string, ids []string) bool {
	server.mu.Lock()
	peer := host.filePeer
	live := server.hosts[host.runtimeID] == host && !host.closing
	server.mu.Unlock()
	if !live || peer == nil || peer.ctx.Err() != nil {
		return false
	}
	peer.mu.Lock()
	defer peer.mu.Unlock()
	for _, file := range ids {
		found := false
		for _, route := range peer.active {
			if route.file == file && route.session == session && route.staged && route.until.After(time.Now().Add(100*time.Millisecond)) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

type filePeer struct {
	server *Server
	live   *liveConnection
	host   files.HostBinding
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	queue  chan wireEnvelope
	mu     sync.Mutex
	active map[string]fileRoute
	window time.Time
	count  int
}

func (server *Server) startFilePeer(parent context.Context, live *liveConnection) *filePeer {
	ctx, cancel := context.WithCancel(parent)
	peer := &filePeer{server: server, live: live, ctx: ctx, cancel: cancel, done: make(chan struct{}), queue: make(chan wireEnvelope, 8), active: make(map[string]fileRoute), host: files.HostBinding{InstallationID: live.peer.installation.InstallationID, KeyVersion: live.peer.installation.KeyVersion, RuntimeID: live.runtimeID, RuntimeEpoch: live.runtimeEpoch, ConnectionID: live.connectionID, CredentialExpiresAt: live.peer.installation.ExpiresAt}}
	go func() {
		defer close(peer.done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case frame := <-peer.queue:
				peer.handle(frame)
			case <-ticker.C:
				peer.offer()
			}
		}
	}()
	return peer
}
func (peer *filePeer) close() { peer.cancel(); <-peer.done }
func (peer *filePeer) enqueue(frame wireEnvelope) bool {
	if frame.RuntimeID != peer.host.RuntimeID || frame.RuntimeEpoch != peer.host.RuntimeEpoch || !uuidPattern.MatchString(frame.RequestID) || frame.UserID != "" || frame.DeviceID != "" || frame.PayloadSHA256 != "" || frame.SubscriptionID != "" || frame.SyncID != "" {
		return false
	}
	now := time.Now()
	if peer.window.IsZero() || now.Sub(peer.window) >= time.Second {
		peer.window = now
		peer.count = 0
	}
	peer.count++
	if peer.count > 20 {
		return false
	}
	select {
	case peer.queue <- frame:
		return true
	default:
		return false
	}
}
func (peer *filePeer) send(kind, request, session string, payload any) error {
	ctx, cancel := context.WithTimeout(peer.ctx, 2*time.Second)
	defer cancel()
	frame := map[string]any{"v": 1, "type": kind, "request_id": request, "runtime_id": peer.host.RuntimeID, "runtime_epoch": peer.host.RuntimeEpoch, "payload": payload}
	if session != "" {
		frame["session_id"] = session
	}
	return peer.live.sendJSON(ctx, frame)
}
func (peer *filePeer) offer() {
	if _, err := peer.server.FileHostLifetime(peer.host); err != nil {
		return
	}
	peer.mu.Lock()
	for id, route := range peer.active {
		if !route.until.After(time.Now()) {
			delete(peer.active, id)
		}
	}
	space := 32 - len(peer.active)
	peer.mu.Unlock()
	if space <= 0 {
		return
	}
	ctx, cancel := context.WithTimeout(peer.ctx, 2*time.Second)
	defer cancel()
	ids, err := peer.server.fileHandoffs.Pending(ctx, peer.host, min(space, 2))
	if err != nil {
		return
	}
	for _, file := range ids {
		offer, err := peer.server.fileHandoffs.Offer(ctx, peer.host, file)
		if err != nil || offer == nil {
			continue
		}
		request, err := randomUUID()
		if err != nil {
			return
		}
		peer.mu.Lock()
		peer.active[offer.HandoffID] = fileRoute{file: offer.FileID, session: offer.SessionID, until: offer.LeaseUntil}
		peer.mu.Unlock()
		if peer.send("file.offer", request, offer.SessionID, offer) != nil {
			_ = peer.server.fileHandoffs.End(ctx, peer.host, offer.HandoffID)
			peer.mu.Lock()
			delete(peer.active, offer.HandoffID)
			peer.mu.Unlock()
			return
		}
	}
}

type fileLeaseItem struct {
	ID         string    `json:"handoff_id"`
	LeaseUntil time.Time `json:"lease_until"`
	ExpiresAt  time.Time `json:"expires_at"`
}

func (peer *filePeer) handle(frame wireEnvelope) {
	ctx, cancel := context.WithTimeout(peer.ctx, 2*time.Second)
	defer cancel()
	if frame.Type == "file.renew" {
		var payload struct {
			IDs []string `json:"handoff_ids"`
		}
		if frame.SessionID != "" || decodePayload(frame.Payload, &payload) != nil || len(payload.IDs) < 1 || len(payload.IDs) > 32 {
			peer.server.sendProtocolError(ctx, peer.live, "protocol.invalid", &frame)
			return
		}
		leases := []fileLeaseItem{}
		seen := map[string]bool{}
		for _, id := range payload.IDs {
			if !uuidPattern.MatchString(id) || seen[id] {
				peer.server.sendProtocolError(ctx, peer.live, "protocol.invalid", &frame)
				return
			}
			seen[id] = true
			peer.mu.Lock()
			_, known := peer.active[id]
			peer.mu.Unlock()
			if !known {
				continue
			}
			handoff, err := peer.server.fileHandoffs.Renew(ctx, peer.host, id)
			if err != nil {
				peer.mu.Lock()
				delete(peer.active, id)
				peer.mu.Unlock()
				continue
			}
			leases = append(leases, fileLeaseItem{ID: id, LeaseUntil: handoff.LeaseUntil, ExpiresAt: handoff.ExpiresAt})
			peer.mu.Lock()
			route := peer.active[id]
			route.until = handoff.LeaseUntil
			peer.active[id] = route
			peer.mu.Unlock()
		}
		_ = peer.send("file.renewed", frame.RequestID, "", map[string]any{"leases": leases})
		return
	}
	var payload struct {
		ID     string `json:"handoff_id"`
		FileID string `json:"file_id"`
		SHA256 string `json:"sha256,omitempty"`
		Size   *int64 `json:"size_bytes,omitempty"`
		Name   string `json:"name,omitempty"`
	}
	if frame.Type == "file.release" {
		var release struct {
			ID     string `json:"handoff_id"`
			FileID string `json:"file_id"`
		}
		if decodePayload(frame.Payload, &release) != nil {
			peer.server.sendProtocolError(ctx, peer.live, "protocol.invalid", &frame)
			return
		}
	}
	if decodePayload(frame.Payload, &payload) != nil || !uuidPattern.MatchString(payload.ID) {
		peer.server.sendProtocolError(ctx, peer.live, "protocol.invalid", &frame)
		return
	}
	peer.mu.Lock()
	route, known := peer.active[payload.ID]
	peer.mu.Unlock()
	if !known || route.file != payload.FileID || route.session != frame.SessionID {
		peer.server.sendProtocolError(ctx, peer.live, "file.stale", &frame)
		return
	}
	var err error
	if frame.Type == "file.staged" {
		if payload.Size == nil {
			peer.server.sendProtocolError(ctx, peer.live, "protocol.invalid", &frame)
			return
		}
		err = peer.server.fileHandoffs.Staged(ctx, peer.host, payload.ID, payload.SHA256, *payload.Size, payload.Name)
	} else {
		err = peer.server.fileHandoffs.End(ctx, peer.host, payload.ID)
		peer.mu.Lock()
		delete(peer.active, payload.ID)
		peer.mu.Unlock()
	}
	if err != nil {
		peer.server.sendProtocolError(ctx, peer.live, "file.stale", &frame)
		return
	}
	if peer.send(frame.Type+".ack", frame.RequestID, frame.SessionID, map[string]any{"handoff_id": payload.ID, "file_id": payload.FileID}) == nil && frame.Type == "file.staged" {
		peer.mu.Lock()
		route := peer.active[payload.ID]
		route.staged = true
		peer.active[payload.ID] = route
		peer.mu.Unlock()
	}
}
