package httpapi_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/relay"
)

func TestProductionNodeQueueLimitsLoadBeforeAdmissionAndRemainLocal(t *testing.T) {
	f := newRoutingFixture(t, 1, 2)
	node := f.nodes["a"]
	node.process.stop(t)
	limits := relay.SendQueueLimits{Version: 1, OrdinaryBytes: 131072, ControlBytes: 65536}
	raw, _ := json.Marshal(limits)
	path := filepath.Join(t.TempDir(), "node-queues.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	binary := os.Getenv("REMOTE_TEST_SERVICE_BIN")
	describe := exec.CommandContext(f.ctx, binary, "queue-limits", "describe")
	describe.Env = []string{"PATH=" + os.Getenv("PATH"), "REMOTE_DATABASE_URL=PRIVATE_INVALID_DSN", "REMOTE_RELAY_QUEUE_LIMITS_FILE=" + path}
	output, err := describe.Output()
	if err != nil {
		t.Fatal("production queue description tried to start a database service", err)
	}
	var configured struct {
		Limits relay.SendQueueLimits `json:"limits"`
	}
	if json.Unmarshal(output, &configured) != nil || configured.Limits != limits {
		t.Fatal("production queue description did not match the protected file")
	}
	environment := append(append([]string{}, node.process.command.Env...), "REMOTE_RELAY_QUEUE_LIMITS_FILE="+path)
	node.process = startSharedProofProcess(t, f.ctx, binary, environment, filepath.Join(t.TempDir(), "queue-node.log"))
	if err := capacityWait(f.ctx, 8*time.Second, func() (bool, error) {
		response, err := f.clients["a"].Get(f.origin + "/readyz")
		if err != nil {
			return false, nil
		}
		_ = response.Body.Close()
		return response.StatusCode == 204, nil
	}); err != nil {
		t.Fatal("node queue configuration did not start", err)
	}
	f.host(f.pairs[0], "a")
	for name, expected := range map[string]relay.SendQueueLimits{"a": limits, "b": relay.DefaultSendQueueLimits()} {
		values, _, err := capacityMetrics(f.clients[name], f.nodes[name].metrics)
		if err != nil {
			t.Fatal(err)
		}
		// Prometheus renders the large default in exponent notation; parse
		// through the existing fixture reader rather than matching formatting.
		if capacityMetric(values, "dsh_remote_relay_send_limit_bytes", map[string]string{"lane": "ordinary"}) != float64(expected.OrdinaryBytes) || capacityMetric(values, "dsh_remote_relay_send_limit_bytes", map[string]string{"lane": "control"}) != float64(expected.ControlBytes) {
			t.Fatal("node payload budget was not applied locally", name)
		}
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	invalid := exec.CommandContext(f.ctx, binary)
	invalid.Env = environment
	output, err = invalid.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "relay send queue limits are invalid") || strings.Contains(string(output), path) {
		t.Fatal("invalid node queue file was accepted or exposed", err)
	}
}
