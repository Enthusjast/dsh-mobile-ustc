package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"dsh-mobile-ustc/services/remote/internal/store"
	"dsh-mobile-ustc/services/remote/internal/testsupport"
)

func TestAuditArchiveCLIRejectsInvalidArgumentsWithoutOpeningDatabase(t *testing.T) {
	t.Setenv("REMOTE_DATABASE_URL", "PRIVATE_INVALID_DSN")
	t.Setenv("REMOTE_DATABASE_EPOCH", store.OriginalDatabaseEpoch)
	id := "aaaaaaaa-1111-4111-8111-111111111111"
	for _, args := range [][]string{
		{"audit"},
		{"audit", "--batch-id", id, "--expected-epoch", store.OriginalDatabaseEpoch, "--limit", "129"},
		{"audit", "--batch-id", id, "--expected-epoch", store.OriginalDatabaseEpoch, "--retention-years", "0"},
		{"audit", "--batch-id", id, "--expected-epoch", "bbbbbbbb-1111-4111-8111-111111111111"},
		{"audit", "--batch-id", id, "--expected-epoch", store.OriginalDatabaseEpoch, "extra"},
	} {
		var output bytes.Buffer
		err := runArchiveCommand(args, &output)
		if err == nil || strings.Contains(err.Error(), "PRIVATE_INVALID_DSN") || output.Len() != 0 {
			t.Fatal("invalid audit archive request succeeded or exposed configuration", err)
		}
	}
}

func TestAuditArchiveProductionBinaryReconcilesLostOutput(t *testing.T) {
	binary := os.Getenv("REMOTE_TEST_SERVICE_BIN")
	if binary == "" {
		t.Skip("explicit disposable production service binary required")
	}
	ctx, database := testsupport.PostgresDatabase(t)
	dsn := archiveTestDSN(t, ctx, database)
	t.Setenv("REMOTE_DATABASE_URL", dsn)
	t.Setenv("REMOTE_DATABASE_EPOCH", store.OriginalDatabaseEpoch)
	id := "aaaaaaaa-1111-4111-8111-111111111111"
	// The isolated fixture simulates an aged row after the production timestamp guard.
	if _, err := database.ExecContext(ctx, `create function test_audit_cli_time() returns trigger language plpgsql as $$
	 begin new.ts='2000-01-01'; return new; end $$;
	 create trigger zz_audit_cli_time before insert on audit_log for each row when(new.actor_id='PRIVATE_AUDIT_ACTOR') execute function test_audit_cli_time()`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `insert into audit_log(ts,actor_type,actor_id,action,result,metadata)
	 values('2000-01-01','system','PRIVATE_AUDIT_ACTOR','fixture.event','success',jsonb_build_object('marker','PRIVATE_AUDIT_BODY'))`); err != nil {
		t.Fatal(err)
	}
	args := []string{"audit", "--batch-id", id, "--expected-epoch", store.OriginalDatabaseEpoch, "--limit", "1"}
	if err := runArchiveCommand(args, archiveFailedOutput{}); err == nil || !strings.Contains(err.Error(), "same batch UUID") || strings.Contains(err.Error(), "PRIVATE_OUTPUT_ERROR") {
		t.Fatal("lost output did not preserve audit archive identity", err)
	}
	command := exec.CommandContext(ctx, binary, append([]string{"archive"}, args...)...)
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "REMOTE_DATABASE_URL=" + dsn, "REMOTE_DATABASE_EPOCH=" + store.OriginalDatabaseEpoch}
	raw, err := command.CombinedOutput()
	if err != nil {
		t.Fatal("production audit archive retry failed", err)
	}
	var result store.AuditArchiveResult
	if json.Unmarshal(raw, &result) != nil || result.BatchID != id || result.Entries != 1 || result.Limit != 1 {
		t.Fatal("production command did not return the original batch")
	}
	for _, private := range []string{"PRIVATE_AUDIT_BODY", "PRIVATE_AUDIT_ACTOR", dsn} {
		if bytes.Contains(raw, []byte(private)) {
			t.Fatal("archive command exposed source data or database connection")
		}
	}
	var hot, history, audits int
	if err := database.QueryRowContext(ctx, `select (select count(*) from audit_log where action='fixture.event'),
	 (select count(*) from audit_log_archive),(select count(*) from audit_log where action='audit.archive.batch')`).Scan(&hot, &history, &audits); err != nil || hot != 0 || history != 1 || audits != 1 {
		t.Fatal("lost-output retry duplicated or lost audit history", hot, history, audits, err)
	}
}
