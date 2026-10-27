package relay

import (
	"testing"

	"github.com/coder/websocket"
	"github.com/prometheus/client_golang/prometheus"
)

// A collector microbenchmark over metadata-only synthetic sockets. It does not
// authenticate, allocate queued bodies, hold actual sockets or prove capacity.
func BenchmarkRelayMetricsCollectionAt12000Sockets(b *testing.B) {
	server := New(nil)
	for i := range 12000 {
		connection := &websocket.Conn{}
		role := "installation"
		if i%2 != 0 {
			role = "device"
		}
		server.connections[connection] = &liveConnection{conn: connection, peer: peer{role: role}, connectionID: "benchmark"}
	}
	registry := prometheus.NewRegistry()
	registry.MustRegister(server)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := registry.Gather(); err != nil {
			b.Fatal(err)
		}
	}
}
