package relay

import (
	"context"
	"strings"
	"sync"
	"time"

	"dsh-mobile-ustc/services/remote/internal/store"
)

func (server *Server) ApplyControlEvent(ctx context.Context, event store.ControlEvent) error {
	if event.Topic == "approval.device.revoked" {
		return server.invalidateHostApprovals(ctx, event)
	}
	if strings.HasPrefix(event.Topic, "approval.") {
		if server.approvals != nil && event.Topic != "approval.authorization.prepared" {
			server.approvals.publish(ctx, event.RuntimeID, event.ApprovalID)
		}
		return nil
	}
	server.mu.Lock()
	connections := []*liveConnection{}
	for _, live := range server.connections {
		if live.peer.role != "device" || live.connectionID == "" || live.closing {
			continue
		}
		matches := event.Topic == "device.revoked" && event.DeviceID == live.peer.deviceID
		if event.Topic == "runtime_grant.updated" || event.Topic == "runtime_grant.revoked" {
			matches = event.RuntimeID == live.runtimeID && event.UserID == live.peer.redemption.UserID && live.peer.redemption.GrantVersion < event.GrantVersion
		}
		if matches {
			live.closing = true
			connections = append(connections, live)
		}
	}
	server.mu.Unlock()
	server.closeRevokedConnections(ctx, connections, "access.revoked")
	if event.Topic == "runtime_grant.updated" || event.Topic == "runtime_grant.revoked" {
		return server.invalidateHostApprovals(ctx, event)
	}
	return nil
}

// A host either observes this scoped negative authority fact or loses its
// connection/cache. Transport acknowledgement is sufficient here: a lost
// connection cannot restore authority, and leases still expire within 3 seconds.
func (server *Server) invalidateHostApprovals(parent context.Context, event store.ControlEvent) error {
	if server.approvals == nil {
		return nil
	}
	host := server.hostForRuntime(event.RuntimeID)
	if host == nil || !host.supports(approvalCapability) {
		return nil
	}
	ctx, cancel := context.WithTimeout(parent, 250*time.Millisecond)
	defer cancel()
	if !host.supports(approvalInvalidationCapability) {
		_ = host.conn.CloseNow()
		return nil
	}
	var payload map[string]any
	if event.Topic == "approval.device.revoked" {
		if !uuidPattern.MatchString(event.DeviceID) {
			return store.ErrGrantInvalid
		}
		payload = map[string]any{"kind": "device.revoked", "device_id": event.DeviceID, "connection_id": host.connectionID}
	} else {
		if !uuidPattern.MatchString(event.UserID) || event.GrantVersion < 1 || event.GrantVersion > 9_007_199_254_740_991 {
			return store.ErrGrantInvalid
		}
		payload = map[string]any{"kind": "grant.changed", "user_id": event.UserID, "grant_version": event.GrantVersion, "connection_id": host.connectionID}
	}
	id := event.ID
	if !uuidPattern.MatchString(id) {
		var err error
		id, err = randomUUID()
		if err != nil {
			_ = host.conn.CloseNow()
			return err
		}
	}
	if err := host.sendJSON(ctx, map[string]any{"v": 1, "type": "approval.invalidate", "request_id": id, "runtime_id": host.runtimeID, "runtime_epoch": host.runtimeEpoch, "payload": payload}); err != nil {
		_ = host.conn.CloseNow()
	}
	return nil
}

func (server *Server) RevalidateConnections(ctx context.Context) error {
	server.mu.Lock()
	connections := []*liveConnection{}
	for _, live := range server.connections {
		if live.connectionID != "" && !live.closing {
			connections = append(connections, live)
		}
	}
	server.mu.Unlock()
	invalid := []*liveConnection{}
	for start := 0; start < len(connections); start += 128 {
		end := min(start+128, len(connections))
		leases := make([]store.RealtimeConnectionLease, 0, end-start)
		byID := make(map[string]*liveConnection, end-start)
		for _, live := range connections[start:end] {
			lease := store.RealtimeConnectionLease{Role: live.peer.role, ConnectionID: live.connectionID, RuntimeID: live.runtimeID}
			if live.peer.role == "installation" {
				if !live.peer.installation.ExpiresAt.After(time.Now()) {
					invalid = append(invalid, live)
					continue
				}
				lease.InstallationID, lease.RuntimeEpoch, lease.KeyVersion = &live.peer.installation.InstallationID, &live.runtimeEpoch, live.peer.installation.KeyVersion
			} else {
				ticket := &live.peer.redemption
				lease.UserID, lease.DeviceID, lease.DeviceKeyVersion = &ticket.UserID, &ticket.DeviceID, ticket.DeviceKeyVersion
				lease.GrantVersion, lease.ProofKeyThumbprint, lease.Scope = ticket.GrantVersion, ticket.ProofKeyThumbprint, ticket.Scope
				if route := live.expectedRoute; route != nil {
					lease.RoutedNodeID, lease.RoutedGeneration = &route.NodeID, &route.Generation
					lease.RoutedEpoch, lease.RoutedConnectionID = &route.RuntimeEpoch, &route.ConnectionID
				}
			}
			leases = append(leases, lease)
			byID[live.connectionID] = live
		}
		ids, err := server.database.InvalidRealtimeConnectionLeases(ctx, leases)
		if err != nil {
			// An expired check deadline must not extend access. Notifications get a
			// separate short deadline; sockets close even when writes fail.
			server.closeRevokedConnections(context.Background(), connections, "internal")
			return err
		}
		for _, id := range ids {
			if live := byID[id]; live != nil {
				invalid = append(invalid, live)
			}
		}
	}
	server.closeRevokedConnections(ctx, invalid, "access.revoked")
	return nil
}

func (server *Server) closeRevokedConnections(parent context.Context, connections []*liveConnection, code string) {
	server.mu.Lock()
	for _, live := range connections {
		live.closing = true
	}
	server.mu.Unlock()
	for _, live := range connections {
		server.countRevocation(live, code)
	}
	ctx, cancel := context.WithTimeout(parent, 250*time.Millisecond)
	defer cancel()
	var writes sync.WaitGroup
	for _, live := range connections {
		writes.Add(1)
		go func(live *liveConnection) {
			defer writes.Done()
			_ = live.sendJSON(ctx, map[string]any{"v": 1, "type": "access.revoked", "payload": map[string]string{"code": code}})
			_ = live.conn.CloseNow()
		}(live)
	}
	writes.Wait()
}

func (server *Server) countRevocation(live *liveConnection, code string) {
	if live.revocationCounted.Swap(true) {
		return
	}
	reason := "access_revoked"
	if code == "internal" {
		reason = "authority_unavailable"
	}
	server.metrics.Revoked(live.peer.role, reason)
}
