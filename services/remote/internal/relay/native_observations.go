package relay

import (
	"context"
	"dsh-mobile-ustc/services/remote/internal/hostmetrics"
	"time"
)

func (server *Server) routeHostObservations(ctx context.Context, live *liveConnection, envelope wireEnvelope) {
	if live.peer.role != "installation" {
		server.metrics.HostObservationReport("denied")
		server.sendProtocolError(ctx, live, "access.denied", &envelope)
		return
	}
	if server.metrics == nil || !live.supports(hostmetrics.Capability) {
		server.sendProtocolError(ctx, live, "protocol.unsupported", &envelope)
		return
	}
	now := time.Now()
	if !live.lastNativeReport.IsZero() && now.Sub(live.lastNativeReport) < time.Second {
		server.metrics.HostObservationReport("throttled")
		return
	}
	live.lastNativeReport = now
	if envelope.RuntimeID != live.runtimeID || envelope.RuntimeEpoch != live.runtimeEpoch || envelope.RequestID != "" || envelope.SessionID != "" || envelope.DeviceID != "" || envelope.UserID != "" || envelope.PayloadSHA256 != "" || envelope.SubscriptionID != "" || envelope.SyncID != "" {
		server.metrics.HostObservationReport("rejected")
		return
	}
	var report hostmetrics.Report
	if len(envelope.Payload) > 16<<10 || decodePayload(envelope.Payload, &report) != nil || report.ConnectionID != live.connectionID {
		server.metrics.HostObservationReport("rejected")
		return
	}
	delta, err := hostmetrics.Difference(live.nativeReport, report)
	if err != nil {
		server.metrics.HostObservationReport("rejected")
		return
	}
	server.mu.Lock()
	current := !server.draining && !live.closing && server.hosts[live.runtimeID] == live
	server.mu.Unlock()
	if !current {
		server.metrics.HostObservationReport("denied")
		return
	}
	check, stop := context.WithTimeout(ctx, 2*time.Second)
	err = server.database.TouchRuntimeConnection(check, live.peer.installation.InstallationID, live.runtimeID, live.runtimeEpoch, live.connectionID)
	stop()
	if err != nil {
		server.metrics.HostObservationReport("denied")
		return
	}
	if delta.Duplicate {
		server.metrics.HostObservationReport("duplicate")
		return
	}
	live.nativeReport = &report
	server.metrics.HostObservations(delta)
	server.metrics.HostObservationReport("accepted")
}
