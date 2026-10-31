package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"dsh-mobile-ustc/services/remote/internal/store"
	"dsh-mobile-ustc/services/remote/internal/testsupport"
)

func TestConnectionPolicyCLIRejectsInvalidArgumentsBeforeDatabase(t *testing.T) {
	t.Setenv("REMOTE_DATABASE_URL", "PRIVATE_INVALID_DATABASE")
	t.Setenv("REMOTE_DATABASE_EPOCH", store.OriginalDatabaseEpoch)
	for _, args := range [][]string{nil, {"unknown"}, {"replace"}, {"replace", "--policy-file", "missing"}, {"status", "--operation-id", "anything"}, {"status", "extra"}} {
		var output bytes.Buffer
		if err := runConnectionLimitCommand(args, &output); err == nil || output.Len() != 0 || strings.Contains(err.Error(), "PRIVATE_INVALID_DATABASE") {
			t.Fatal("invalid policy operation reached database or output", args, err)
		}
	}
	t.Setenv("REMOTE_DATABASE_EPOCH", "invalid")
	var output bytes.Buffer
	if err := runConnectionLimitCommand([]string{"status"}, &output); err != errConnectionLimitConfiguration {
		t.Fatal("invalid epoch reached database", err)
	}
}

func TestConnectionPolicyCLIReconcilesLostOutputWithProductionBinary(t *testing.T) {
	binary := os.Getenv("REMOTE_TEST_SERVICE_BIN")
	if binary == "" {
		t.Skip("explicit disposable production service binary required")
	}
	ctx, db := testsupport.PostgresDatabase(t)
	dsn := archiveTestDSN(t, ctx, db)
	t.Setenv("REMOTE_DATABASE_URL", dsn)
	t.Setenv("REMOTE_DATABASE_EPOCH", store.OriginalDatabaseEpoch)
	repository := &store.Postgres{DB: db}
	limits := store.DefaultConnectionLimits()
	if err := repository.ConfigureConnectionLimits(ctx, limits); err != nil {
		t.Fatal(err)
	}
	digest, _ := limits.PolicyDigest()
	updated := limits
	updated.Device++
	raw, _ := json.Marshal(updated)
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"replace", "--operation-id", "aaaaaaaa-1111-4111-8111-111111111111", "--expected-sha256", hex.EncodeToString(digest[:]), "--policy-file", path}
	if err := runConnectionLimitCommand(args, archiveFailedOutput{}); err == nil || !strings.Contains(err.Error(), "same operation UUID") || strings.Contains(err.Error(), "PRIVATE_OUTPUT_ERROR") {
		t.Fatal("lost policy output was not reconcilable", err)
	}
	consumer, err := repository.NewControlConsumer(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	defer consumer.Release(ctx)
	command := exec.CommandContext(ctx, binary, append([]string{"connection-limits"}, args...)...)
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "REMOTE_DATABASE_URL=" + dsn, "REMOTE_DATABASE_EPOCH=" + store.OriginalDatabaseEpoch}
	output, err := command.Output()
	if err != nil {
		t.Fatal("production policy retry failed", err)
	}
	var receipt store.ConnectionPolicyChange
	if json.Unmarshal(output, &receipt) != nil || receipt.Policy != updated || receipt.OperationID != args[2] {
		t.Fatal("policy retry returned wrong receipt")
	}
	var count int
	if err := db.QueryRowContext(ctx, `select count(*) from audit_log where action='connection_policy.replace'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("policy retry repeated audit", count, err)
	}
}
