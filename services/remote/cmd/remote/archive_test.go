package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"dsh-mobile-ustc/services/remote/internal/store"
	"dsh-mobile-ustc/services/remote/internal/testsupport"
	"github.com/jackc/pgx/v5"
)

type archiveFailedOutput struct{}

func (archiveFailedOutput) Write([]byte) (int, error) { return 0, errors.New("PRIVATE_OUTPUT_ERROR") }

func archiveTestDSN(t *testing.T, ctx context.Context, db *sql.DB) string {
	t.Helper()
	config, err := pgx.ParseConfig(os.Getenv("REMOTE_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal("invalid disposable database configuration")
	}
	var database string
	if err := db.QueryRowContext(ctx, `select current_database()`).Scan(&database); err != nil {
		t.Fatal(err)
	}
	quote := func(value string) string {
		return "'" + strings.ReplaceAll(strings.ReplaceAll(value, `\`, `\\`), `'`, `\'`) + "'"
	}
	return "host=" + quote(config.Host) + " port=" + strconv.Itoa(int(config.Port)) + " user=" + quote(config.User) + " password=" + quote(config.Password) + " dbname=" + quote(database) + " sslmode=disable"
}

func TestArchiveControlCLIRejectsInvalidArgumentsBeforeOpeningDatabase(t *testing.T) {
	t.Setenv("REMOTE_DATABASE_EPOCH", store.OriginalDatabaseEpoch)
	t.Setenv("REMOTE_DATABASE_URL", "PRIVATE_INVALID_DSN")
	validID := "aaaaaaaa-1111-4111-8111-111111111111"
	for _, args := range [][]string{nil, {"unknown"}, {"control"}, {"control", "--batch-id", "bad", "--expected-epoch", store.OriginalDatabaseEpoch},
		{"control", "--batch-id", validID, "--expected-epoch", store.OriginalDatabaseEpoch, "--limit", "129"},
		{"control", "--batch-id", validID, "--expected-epoch", store.OriginalDatabaseEpoch, "--retention-years", "0"},
		{"control", "--batch-id", validID, "--expected-epoch", "bbbbbbbb-1111-4111-8111-111111111111"},
		{"control", "--batch-id", validID, "--expected-epoch", store.OriginalDatabaseEpoch, "extra"}} {
		var output bytes.Buffer
		err := runArchiveCommand(args, &output)
		if err == nil || strings.Contains(err.Error(), "PRIVATE_INVALID_DSN") || output.Len() != 0 {
			t.Fatal("invalid archive arguments exposed state or succeeded", err)
		}
	}
}

func TestArchiveControlCLIReconcilesLostOutputAndProductionBinary(t *testing.T) {
	binary := os.Getenv("REMOTE_TEST_SERVICE_BIN")
	if binary == "" {
		t.Skip("explicit disposable production service binary required")
	}
	ctx, db := testsupport.PostgresDatabase(t)
	dsn := archiveTestDSN(t, ctx, db)
	t.Setenv("REMOTE_DATABASE_URL", dsn)
	t.Setenv("REMOTE_DATABASE_EPOCH", store.OriginalDatabaseEpoch)
	batch := "aaaaaaaa-1111-4111-8111-111111111111"
	device := "dddddddd-1111-4111-8111-111111111111"
	if _, err := db.ExecContext(ctx, `insert into control_outbox(topic,payload,created_at,published_at)
	 values('device.revoked',jsonb_build_object('device_id',$1::text,'marker','PRIVATE_ARCHIVE_METADATA'),'2000-01-01','2000-01-02')`, device); err != nil {
		t.Fatal(err)
	}
	args := []string{"control", "--batch-id", batch, "--expected-epoch", store.OriginalDatabaseEpoch, "--limit", "1"}
	err := runArchiveCommand(args, archiveFailedOutput{})
	if err == nil || !strings.Contains(err.Error(), "same batch UUID") || strings.Contains(err.Error(), "PRIVATE_OUTPUT_ERROR") {
		t.Fatal("lost output did not request safe reconciliation", err)
	}
	command := exec.CommandContext(ctx, binary, append([]string{"archive"}, args...)...)
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "REMOTE_DATABASE_URL=" + dsn, "REMOTE_DATABASE_EPOCH=" + store.OriginalDatabaseEpoch}
	raw, err := command.CombinedOutput()
	if err != nil {
		t.Fatal("production archive retry failed", err)
	}
	var result store.ControlArchiveResult
	if json.Unmarshal(raw, &result) != nil || result.BatchID != batch || result.Events != 1 || result.Limit != 1 {
		t.Fatal("production CLI did not return the original committed result")
	}
	if bytes.Contains(raw, []byte("PRIVATE_ARCHIVE_METADATA")) || bytes.Contains(raw, []byte(device)) || bytes.Contains(raw, []byte(dsn)) {
		t.Fatal("archive CLI exposed source payload or database connection")
	}
	var hot, cold, audits int
	if err := db.QueryRowContext(ctx, `select (select count(*) from control_outbox),(select count(*) from control_outbox_archive),(select count(*) from audit_log where action='control.archive')`).Scan(&hot, &cold, &audits); err != nil || hot != 0 || cold != 1 || audits != 1 {
		t.Fatal("lost-output retry duplicated or lost the archive", hot, cold, audits, err)
	}
	command = exec.CommandContext(ctx, binary, "archive", "control", "--batch-id", batch, "--expected-epoch", store.OriginalDatabaseEpoch, "--limit", "2")
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "REMOTE_DATABASE_URL=" + dsn, "REMOTE_DATABASE_EPOCH=" + store.OriginalDatabaseEpoch}
	if output, err := command.CombinedOutput(); err == nil || !strings.Contains(string(output), "control archive operation conflicts") || bytes.Contains(output, []byte("PRIVATE_ARCHIVE_METADATA")) {
		t.Fatal("changed operation parameters were not refused safely", fmt.Sprint(err))
	}
}
