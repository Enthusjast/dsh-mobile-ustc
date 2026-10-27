package observability

import (
	"testing"
	"time"
)

// Measures only observer calls, not encoding, queues, transport or native work.
func BenchmarkFrameMetrics(b *testing.B) {
	for _, enabled := range []bool{false, true} {
		name := "disabled"
		var metrics *Metrics
		if enabled {
			name, metrics = "enabled", New()
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			b.RunParallel(func(p *testing.PB) {
				for p.Next() {
					metrics.Received("installation", 512)
					metrics.Dequeued("device", time.Millisecond)
					metrics.Written("device", 512, 2*time.Millisecond, nil)
				}
			})
		})
	}
}
