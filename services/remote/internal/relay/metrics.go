package relay

import (
	"strconv"

	"dsh-mobile-ustc/services/remote/internal/observability"
	"github.com/prometheus/client_golang/prometheus"
)

var queueByteBuckets = []float64{0, 1024, 4096, 16384, 65536, 262144, 1048576}

func relayDesc(name, help string, labels ...string) *prometheus.Desc {
	return prometheus.NewDesc("dsh_remote_relay_"+name, help, labels, nil)
}

var relayMetricDescriptions = []*prometheus.Desc{
	relayDesc("connections", "Upgraded sockets by role and handshake/lifecycle phase.", "role", "phase"),
	relayDesc("queued_messages", "Current queued data messages, excluding the in-flight writer.", "role"),
	relayDesc("queued_bytes", "Current queued serialized payload bytes, excluding the in-flight writer and transport buffers.", "role"),
	relayDesc("inflight_bytes", "Serialized payload bytes currently held by the single writer.", "role"),
	relayDesc("max_connection_queued_bytes", "Largest current per-connection queue, not a historical peak.", "role"),
	relayDesc("queued_connections", "Current sockets with at most bytes_le queued payload bytes; cumulative gauge, not a counter histogram.", "role", "bytes_le"),
	relayDesc("subscriptions", "Current relay-owned read subscriptions."),
	relayDesc("catalog_assembly_bytes", "Current session catalog assembly payload bytes."),
	relayDesc("creation_options_bytes", "Current connection-local session creation options bytes."),
	relayDesc("draining", "One after the relay begins draining."),
	relayDesc("proxy_tunnels", "Current ingress proxy tunnels, including pending owner admission; distinct from owner sockets."),
	relayDesc("proxy_inflight_bytes", "Proxy payload bytes held between read and write; no user-space backlog.", "direction"),
}

// ConfigureMetrics is called once before serving; the registry and collector
// belong to this service, with no global registration or resource-ID labels.
func (server *Server) ConfigureMetrics(metrics *observability.Metrics) {
	server.metrics = metrics
	metrics.Register(server)
}

func (server *Server) Describe(out chan<- *prometheus.Desc) {
	for _, desc := range relayMetricDescriptions {
		out <- desc
	}
}

func (server *Server) Collect(out chan<- prometheus.Metric) {
	type roleSnapshot struct {
		connections                        [3]uint64
		messages, bytes, inflight, maximum int64
		count                              uint64
		buckets                            map[float64]uint64
	}
	roles := []string{"installation", "device", "other"}
	snapshots := make([]roleSnapshot, len(roles))
	for i := range snapshots {
		snapshots[i].buckets = make(map[float64]uint64, len(queueByteBuckets))
		for _, bound := range queueByteBuckets {
			snapshots[i].buckets[bound] = 0
		}
	}
	server.mu.Lock()
	for _, live := range server.connections {
		index := 2
		if live.peer.role == "installation" {
			index = 0
		} else if live.peer.role == "device" {
			index = 1
		}
		snapshot := &snapshots[index]
		phase := 0
		if live.connectionID != "" {
			phase = 1
		}
		if live.closing {
			phase = 2
		}
		snapshot.connections[phase]++
		live.queueMu.Lock()
		messages, bytes, inflight := live.queuedMessages, live.queuedBytes, live.inflightBytes
		live.queueMu.Unlock()
		snapshot.messages += messages
		snapshot.bytes += bytes
		snapshot.inflight += inflight
		snapshot.maximum = max(snapshot.maximum, bytes)
		snapshot.count++
		for _, bound := range queueByteBuckets {
			if float64(bytes) <= bound {
				snapshot.buckets[bound]++
			}
		}
	}
	subscriptions, catalog, options := len(server.subscriptions), server.catalogBytes, server.creationOptionsBytes
	tunnels := len(server.tunnels)
	var inflight [2]int64
	for tunnel := range server.tunnels {
		for i := range inflight {
			inflight[i] += tunnel.inflight[i].Load()
		}
	}
	draining := float64(0)
	if server.draining {
		draining = 1
	}
	server.mu.Unlock()
	// Never hold application locks while emitting to the scrape channel.
	for i, role := range roles {
		snapshot := snapshots[i]
		for phase, label := range []string{"handshaking", "active", "closing"} {
			out <- prometheus.MustNewConstMetric(relayMetricDescriptions[0], prometheus.GaugeValue, float64(snapshot.connections[phase]), role, label)
		}
		for j, value := range []int64{snapshot.messages, snapshot.bytes, snapshot.inflight, snapshot.maximum} {
			out <- prometheus.MustNewConstMetric(relayMetricDescriptions[j+1], prometheus.GaugeValue, float64(value), role)
		}
		for _, bound := range queueByteBuckets {
			out <- prometheus.MustNewConstMetric(relayMetricDescriptions[5], prometheus.GaugeValue, float64(snapshot.buckets[bound]), role, strconv.FormatFloat(bound, 'f', -1, 64))
		}
		out <- prometheus.MustNewConstMetric(relayMetricDescriptions[5], prometheus.GaugeValue, float64(snapshot.count), role, "+Inf")
	}
	for i, value := range []float64{float64(subscriptions), float64(catalog), float64(options), draining} {
		out <- prometheus.MustNewConstMetric(relayMetricDescriptions[i+6], prometheus.GaugeValue, value)
	}
	out <- prometheus.MustNewConstMetric(relayMetricDescriptions[10], prometheus.GaugeValue, float64(tunnels))
	for i, label := range []string{"phone_to_owner", "owner_to_phone"} {
		out <- prometheus.MustNewConstMetric(relayMetricDescriptions[11], prometheus.GaugeValue, float64(inflight[i]), label)
	}
}
