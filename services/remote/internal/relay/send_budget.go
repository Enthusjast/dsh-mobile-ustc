package relay

import (
	"bytes"
	"encoding/json"
	"sync"

	"dsh-mobile-ustc/services/remote/internal/canonical"
	"dsh-mobile-ustc/services/remote/internal/store"
)

// These process-local payload limits include waiting frames and the writer.
// They are memory admission limits, independent of shared connection quotas.
type SendQueueLimits struct {
	Version       int   `json:"v"`
	OrdinaryBytes int64 `json:"ordinary_bytes"`
	ControlBytes  int64 `json:"control_bytes"`
}

func DefaultSendQueueLimits() SendQueueLimits {
	return SendQueueLimits{Version: 1, OrdinaryBytes: 256 << 20, ControlBytes: 16 << 20}
}

func (limits SendQueueLimits) Validate() error {
	if limits.Version != 1 || limits.OrdinaryBytes < maxFrameBytes || limits.OrdinaryBytes > 8<<30 ||
		limits.ControlBytes < maxFrameBytes || limits.ControlBytes > 256<<20 || limits.ControlBytes > limits.OrdinaryBytes {
		return store.ErrDatabaseConfig
	}
	return nil
}

func ParseSendQueueLimits(raw []byte) (SendQueueLimits, error) {
	var limits SendQueueLimits
	if len(raw) > 4096 {
		return limits, store.ErrDatabaseConfig
	}
	if _, err := canonical.Object(raw); err != nil {
		return limits, store.ErrDatabaseConfig
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 3 || fields["v"] == nil || fields["ordinary_bytes"] == nil || fields["control_bytes"] == nil {
		return limits, store.ErrDatabaseConfig
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&limits) != nil || limits.Validate() != nil {
		return limits, store.ErrDatabaseConfig
	}
	return limits, nil
}

type sendQueueBudget struct {
	mu     sync.Mutex
	limits SendQueueLimits
	used   [2]int64
}

func sendBudgetLane(control bool) int {
	if control {
		return 1
	}
	return 0
}

func (budget *sendQueueBudget) reserve(size int, control bool) bool {
	if budget == nil { // Explicit component fixtures may construct their own liveConnection.
		return true
	}
	budget.mu.Lock()
	defer budget.mu.Unlock()
	lane := sendBudgetLane(control)
	limit := budget.limits.OrdinaryBytes
	if control {
		limit = budget.limits.ControlBytes
	}
	if int64(size) > limit-budget.used[lane] {
		return false
	}
	budget.used[lane] += int64(size)
	return true
}

func (budget *sendQueueBudget) release(size int, control bool) {
	if budget == nil {
		return
	}
	budget.mu.Lock()
	defer budget.mu.Unlock()
	budget.used[sendBudgetLane(control)] -= int64(size)
}

func (budget *sendQueueBudget) snapshot() ([2]int64, SendQueueLimits) {
	if budget == nil {
		return [2]int64{}, SendQueueLimits{}
	}
	budget.mu.Lock()
	defer budget.mu.Unlock()
	return budget.used, budget.limits
}

// Startup-only; connection removal must never allow replacing a budget still
// held by an old writer. Node budgets may differ with local memory capacity.
func (server *Server) ConfigureSendQueueLimits(limits SendQueueLimits) error {
	server.mu.Lock()
	defer server.mu.Unlock()
	if limits.Validate() != nil || server.sendBudgetConfigured || server.sendBudgetStarted {
		return store.ErrDatabaseConfig
	}
	server.sendBudget = &sendQueueBudget{limits: limits}
	server.sendBudgetConfigured = true
	return nil
}
