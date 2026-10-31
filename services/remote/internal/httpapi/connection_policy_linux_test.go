package httpapi_test

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/store"
)

func TestProductionConnectionPolicyCLIRequiresDrainAndFencesStaleStartup(t *testing.T) {
	limits := store.ConnectionLimits{Version: 1, Total: 10, User: 10, Device: 2, Installation: 10, PendingHandshakes: 4}
	f := newRoutingFixtureWithConnections(t, 1, 2, &limits)
	dsn, err := capacityDatabaseDSN(f.ctx, f.db)
	if err != nil {
		t.Fatal(err)
	}
	binary := os.Getenv("REMOTE_TEST_SERVICE_BIN")
	env := []string{"PATH=" + os.Getenv("PATH"), "REMOTE_DATABASE_URL=" + dsn, "REMOTE_DATABASE_EPOCH=" + store.OriginalDatabaseEpoch}
	call := func(args ...string) ([]byte, error) {
		command := exec.CommandContext(f.ctx, binary, append([]string{"connection-limits"}, args...)...)
		command.Env = env
		return command.Output()
	}
	output, err := call("status")
	if err != nil {
		t.Fatal(err)
	}
	var status store.ConnectionPolicyStatus
	if json.Unmarshal(output, &status) != nil || status.ActiveConsumers != 2 || status.Policy == nil || *status.Policy != limits {
		t.Fatal("status did not report active production nodes")
	}
	updated := limits
	updated.Device++
	raw, _ := json.Marshal(updated)
	path := filepath.Join(t.TempDir(), "new-limits.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	digest, _ := limits.PolicyDigest()
	args := []string{"replace", "--operation-id", capacityID(), "--expected-sha256", hex.EncodeToString(digest[:]), "--policy-file", path}
	blocked, replaceErr := call(args...)
	var blockedExit *exec.ExitError
	if replaceErr == nil || len(blocked) != 0 || !errors.As(replaceErr, &blockedExit) || !strings.Contains(string(blockedExit.Stderr), "drained") {
		t.Fatal("live production nodes did not enforce drain", replaceErr)
	}
	f.nodes["a"].process.stop(t)
	f.nodes["b"].process.stop(t)
	output, err = call(args...)
	if err != nil {
		t.Fatal("drained policy replacement failed", err)
	}
	var receipt store.ConnectionPolicyChange
	if json.Unmarshal(output, &receipt) != nil || receipt.Policy != updated {
		t.Fatal("invalid replacement receipt")
	}
	// A stale process registers first, fails policy validation, and must release
	// its consumer before exiting without opening a business listener.
	stale := exec.CommandContext(f.ctx, binary)
	stale.Env = f.nodes["b"].process.command.Env
	staleOutput, staleErr := stale.CombinedOutput()
	if staleErr == nil || !strings.Contains(string(staleOutput), "shared connection limits") {
		t.Fatal("stale startup did not fail policy validation", staleErr)
	}
	var staleGeneration string
	var released bool
	if err := f.db.QueryRowContext(f.ctx, `select generation::text,lease_until<=clock_timestamp() from control_consumers where node_id=$1`, f.nodes["b"].id).Scan(&staleGeneration, &released); err != nil || staleGeneration == f.nodes["b"].generation || !released {
		t.Fatal("failed policy startup did not release new consumer", released, err)
	}
	updatedEnv := append([]string{}, f.nodes["a"].process.command.Env...)
	for index, value := range updatedEnv {
		if strings.HasPrefix(value, "REMOTE_CONNECTION_LIMITS_FILE=") {
			updatedEnv[index] = "REMOTE_CONNECTION_LIMITS_FILE=" + path
		}
	}
	node := f.nodes["a"]
	node.process = startSharedProofProcess(t, f.ctx, binary, updatedEnv, filepath.Join(t.TempDir(), "updated-node.log"))
	if err := capacityWait(f.ctx, 8*time.Second, func() (bool, error) {
		client := *f.clients["a"]
		client.Timeout = time.Second
		response, err := client.Get(f.origin + "/readyz")
		if err != nil {
			return false, nil
		}
		_ = response.Body.Close()
		return response.StatusCode == 204, nil
	}); err != nil {
		t.Fatal("updated node did not become ready", err)
	}
	output, err = call(args...)
	if err != nil {
		t.Fatal("retry required another drain", err)
	}
	var retry store.ConnectionPolicyChange
	if json.Unmarshal(output, &retry) != nil || retry != receipt {
		t.Fatal("online retry changed retained policy receipt")
	}
	output, err = call("status")
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(output, &status) != nil || status.ActiveConsumers != 1 || status.Policy == nil || *status.Policy != updated {
		t.Fatal("stale startup retained consumer or policy changed")
	}
}
