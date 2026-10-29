package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auditarchive"
	"dsh-mobile-ustc/services/remote/internal/coldarchive"
	"dsh-mobile-ustc/services/remote/internal/testsupport"
	"github.com/jackc/pgx/v5"
)

func auditColdFixtureDSN(t *testing.T, ctx context.Context, database *sql.DB) string {
	t.Helper()
	config, err := pgx.ParseConfig(os.Getenv("REMOTE_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal("invalid disposable database configuration")
	}
	var name string
	if err := database.QueryRowContext(ctx, `select current_database()`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	quote := func(value string) string {
		return "'" + strings.ReplaceAll(strings.ReplaceAll(value, `\`, `\\`), `'`, `\'`) + "'"
	}
	return "host=" + quote(config.Host) + " port=" + strconv.Itoa(int(config.Port)) + " user=" + quote(config.User) + " password=" + quote(config.Password) + " dbname=" + quote(name) + " sslmode=disable"
}

func TestAuditColdExportProductionBinaryRecoversAndVerifiesWithoutDisclosure(t *testing.T) {
	binary := os.Getenv("REMOTE_TEST_SERVICE_BIN")
	if binary == "" {
		t.Skip("explicit disposable production service binary required")
	}
	ctx, db, request, _ := auditColdFixture(t)
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "audit.key")
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{51}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := coldarchive.OpenDirectoryWithLimit(directory, auditarchive.MaxArtifact)
	if err != nil {
		t.Fatal(err)
	}
	request.DestinationFingerprint, err = root.Fingerprint(request.Key)
	_ = root.Close()
	if err != nil {
		t.Fatal(err)
	}
	state, original, err := db.PrepareAuditColdExport(ctx, request)
	if err != nil || state.State != "prepared" {
		t.Fatal("fixture audit export preparation failed", err)
	}
	dsn := auditColdFixtureDSN(t, ctx, db.DB)
	environment := []string{"PATH=" + os.Getenv("PATH"), "REMOTE_DATABASE_URL=" + dsn, "REMOTE_DATABASE_EPOCH=" + request.DatabaseEpoch, "REMOTE_ARCHIVE_DOMAIN_ID=" + request.DomainID}
	privateValues := []string{"PRIVATE_AUDIT_COLD_BODY", keyPath, directory, dsn}
	arguments := []string{"--export-id", request.ExportID, "--domain-id", request.DomainID, "--batch-id", request.BatchID,
		"--expected-epoch", request.DatabaseEpoch, "--key-id", request.Key.ID(), "--key-file", keyPath, "--directory", directory}
	run := func(command string, args []string, success bool) []byte {
		t.Helper()
		process := exec.CommandContext(ctx, binary, append([]string{"archive", command}, args...)...)
		process.Env = environment
		if command == "verify-audit-offline" {
			process.Env = []string{"PATH=" + os.Getenv("PATH"), "REMOTE_ARCHIVE_DOMAIN_ID=" + request.DomainID}
		}
		raw, err := process.CombinedOutput()
		if success && err != nil || !success && err == nil {
			t.Fatal("production audit cold command had unexpected result", err)
		}
		for _, private := range privateValues {
			if bytes.Contains(raw, []byte(private)) {
				t.Fatal("production audit cold command exposed protected data")
			}
		}
		return raw
	}
	var summary struct {
		ExportID     string `json:"export_id"`
		State        string `json:"state"`
		Verification string `json:"verification"`
		Entries      int    `json:"entries"`
	}
	if raw := run("export-audit", arguments, true); json.Unmarshal(raw, &summary) != nil || summary.ExportID != request.ExportID || summary.State != "published" || summary.Entries != 1 {
		t.Fatal("prepared audit export did not publish")
	}
	filename := request.ExportID + ".dshca"
	file := filepath.Join(directory, filename)
	body, err := os.ReadFile(file)
	if err != nil || !bytes.Equal(body, original) || bytes.Contains(body, []byte("PRIVATE_AUDIT_COLD_BODY")) {
		t.Fatal("retry did not publish original encrypted audit", err)
	}
	offline := []string{"--export-id", request.ExportID, "--domain-id", request.DomainID, "--key-id", request.Key.ID(), "--key-file", keyPath, "--directory", directory}
	if raw := run("verify-audit-offline", offline, true); json.Unmarshal(raw, &summary) != nil || summary.Verification != "offline" || summary.Entries != 1 {
		t.Fatal("offline audit verification scope was not reported")
	}
	copyDir := t.TempDir()
	privateValues = append(privateValues, copyDir)
	if err := os.Chmod(copyDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(copyDir, filename), body, 0600); err != nil {
		t.Fatal(err)
	}
	copyArgs := append([]string(nil), arguments...)
	copyArgs[len(copyArgs)-1] = copyDir
	if raw := run("verify-audit-export", copyArgs, true); json.Unmarshal(raw, &summary) != nil || summary.Verification != "database_audited" {
		t.Fatal("copied audit artifact was not verified and audited")
	}
	run("export-audit", copyArgs, false)
	restoredCtx, restoredDB, restoredDSN := testsupport.RestoredPostgresDatabase(t, db.DB)
	restored := &Postgres{DB: restoredDB}
	epoch, operation := approvalTestUUID(t), approvalTestUUID(t)
	if _, err := restored.QuarantineRecovery(restoredCtx, operation, OriginalDatabaseEpoch, epoch); err != nil {
		t.Fatal(err)
	}
	manifest := RecoveryAuthority{Version: 1, Complete: true, RecoveryID: operation, DatabaseEpoch: epoch, Issuer: "https://id.example.edu", CapturedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Minute).UTC(), Users: []RecoveryUser{}}
	if _, err := restored.ReleaseRecovery(restoredCtx, epoch, manifest.Issuer, manifest); err != nil {
		t.Fatal(err)
	}
	oldEnvironment := environment
	privateValues = append(privateValues, restoredDSN)
	environment = []string{"PATH=" + os.Getenv("PATH"), "REMOTE_DATABASE_URL=" + restoredDSN, "REMOTE_DATABASE_EPOCH=" + epoch, "REMOTE_ARCHIVE_DOMAIN_ID=" + request.DomainID}
	restoredArgs := append([]string(nil), copyArgs...)
	restoredArgs[7] = epoch
	if raw := run("verify-audit-export", restoredArgs, true); json.Unmarshal(raw, &summary) != nil || summary.Verification != "database_audited" {
		t.Fatal("audit copy failed verification after actual recovery")
	}
	run("export-audit", restoredArgs, false)
	newID := approvalTestUUID(t)
	newArgs := append([]string(nil), restoredArgs...)
	newArgs[1] = newID
	run("export-audit", newArgs, true)
	newBody, err := os.ReadFile(filepath.Join(copyDir, newID+".dshca"))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := auditarchive.Open(request.Key, newBody, request.DomainID, newID)
	if err != nil || payload.OperationEpoch != epoch || len(payload.Recoveries) != 1 || payload.Recoveries[0].ID != operation {
		t.Fatal("new audit artifact lost recovery lineage", err)
	}
	auditarchive.Clear(&payload)
	environment = oldEnvironment
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `create function test_fail_audit_repair() returns trigger language plpgsql as $$
	 begin if new.action='audit.cold.export.repair_started' then raise exception 'fixture failure'; end if; return new; end $$;
	 create trigger test_fail_audit_repair before insert on audit_log for each row execute function test_fail_audit_repair()`); err != nil {
		t.Fatal(err)
	}
	run("export-audit", arguments, false)
	if _, err := os.Stat(file); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("repair wrote before its audit intent", err)
	}
	if _, err := db.DB.ExecContext(ctx, `drop trigger test_fail_audit_repair on audit_log; drop function test_fail_audit_repair()`); err != nil {
		t.Fatal(err)
	}
	run("export-audit", arguments, true)
	repaired, err := os.ReadFile(file)
	if err != nil || !bytes.Equal(repaired, original) {
		t.Fatal("missing audit artifact was not repaired", err)
	}
	var starts, repairs, verified int
	if err := db.DB.QueryRowContext(ctx, `select count(*) filter(where action='audit.cold.export.repair_started'),
	 count(*) filter(where action='audit.cold.export.repaired'),count(*) filter(where action='audit.cold.export.verified') from audit_log`).Scan(&starts, &repairs, &verified); err != nil || starts != 1 || repairs != 1 || verified != 1 {
		t.Fatal("audit export repair or verification was not recorded", starts, repairs, verified, err)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `create function test_fail_audit_repair() returns trigger language plpgsql as $$
	 begin if new.action='audit.cold.export.repaired' then raise exception 'fixture failure'; end if; return new; end $$;
	 create trigger test_fail_audit_repair before insert on audit_log for each row execute function test_fail_audit_repair()`); err != nil {
		t.Fatal(err)
	}
	run("export-audit", arguments, false)
	if body, err := os.ReadFile(file); err != nil || !bytes.Equal(body, original) {
		t.Fatal("fixture did not reach post-publication audit failure", err)
	}
	if _, err := db.DB.ExecContext(ctx, `drop trigger test_fail_audit_repair on audit_log; drop function test_fail_audit_repair()`); err != nil {
		t.Fatal(err)
	}
	run("export-audit", arguments, true)
	if err := db.DB.QueryRowContext(ctx, `select count(*) filter(where action='audit.cold.export.repair_started'),
	 count(*) filter(where action='audit.cold.export.repaired'),count(*) filter(where action='audit.cold.export.verified') from audit_log`).Scan(&starts, &repairs, &verified); err != nil || starts != 2 || repairs != 1 || verified != 2 {
		t.Fatal("retry did not reconcile interrupted audit repair", starts, repairs, verified, err)
	}
	repaired, err = os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	repaired[len(repaired)-1] ^= 1
	if err := os.WriteFile(file, repaired, 0600); err != nil {
		t.Fatal(err)
	}
	run("export-audit", arguments, false)
	remaining, err := os.ReadFile(file)
	if err != nil || !bytes.Equal(remaining, repaired) {
		t.Fatal("conflicting audit artifact was overwritten", err)
	}
	run("verify-audit-offline", offline, false)
	t.Run("lost-output", func(t *testing.T) {
		full, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
		if err != nil {
			t.Skip("fixture requires /dev/full")
		}
		defer full.Close()
		newID := approvalTestUUID(t)
		newArgs := append([]string(nil), arguments...)
		newArgs[1] = newID
		process := exec.CommandContext(ctx, binary, append([]string{"archive", "export-audit"}, newArgs...)...)
		process.Env, process.Stdout = environment, full
		var stderr bytes.Buffer
		process.Stderr = &stderr
		if err := process.Run(); err == nil || !strings.Contains(stderr.String(), "same export UUID") {
			t.Fatal("lost output did not retain audit export identity", err)
		}
		for _, private := range privateValues {
			if strings.Contains(stderr.String(), private) {
				t.Fatal("lost-output error exposed protected data")
			}
		}
		run("export-audit", newArgs, true)
		var prepared, published int
		if err := db.DB.QueryRowContext(ctx, `select count(*) filter(where action='audit.cold.export.prepared' and metadata->>'export_id'=$1),
		 count(*) filter(where action='audit.cold.export.published' and metadata->>'export_id'=$1) from audit_log`, newID).Scan(&prepared, &published); err != nil || prepared != 1 || published != 1 {
			t.Fatal("lost-output retry duplicated audit export", prepared, published, err)
		}
	})
}
