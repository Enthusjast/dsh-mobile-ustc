package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/coldarchive"
	"dsh-mobile-ustc/services/remote/internal/evidencearchive"
	"dsh-mobile-ustc/services/remote/internal/testsupport"
)

func TestEvidenceExportProductionBinaryRecoversAndVerifiesWithoutDisclosure(t *testing.T) {
	binary := os.Getenv("REMOTE_TEST_SERVICE_BIN")
	if binary == "" {
		t.Skip("explicit disposable production service binary required")
	}
	f, request, compact := evidenceExportFixture(t)
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "evidence.key")
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{42}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := coldarchive.OpenDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	request.DestinationFingerprint, err = root.Fingerprint(request.Key)
	_ = root.Close()
	if err != nil {
		t.Fatal(err)
	}
	state, original, err := f.database.PrepareEvidenceExport(f.ctx, request)
	if err != nil || state.State != "prepared" {
		t.Fatal("fixture preparation failed", err)
	}
	dsn := evidenceFixtureDSN(t, f)
	environment := []string{"PATH=" + os.Getenv("PATH"), "REMOTE_DATABASE_URL=" + dsn, "REMOTE_DATABASE_EPOCH=" + request.DatabaseEpoch, "REMOTE_ARCHIVE_DOMAIN_ID=" + request.DomainID}
	privateValues := []string{compact, f.ticket.UserID, f.ticket.DeviceID, "private-tool-argument", keyPath, directory, dsn}
	arguments := []string{"--export-id", request.ExportID, "--domain-id", request.DomainID, "--approval-id", request.ApprovalID,
		"--expected-epoch", request.DatabaseEpoch, "--key-id", request.Key.ID(), "--key-file", keyPath, "--directory", directory}
	run := func(command string, args []string, success bool) []byte {
		t.Helper()
		process := exec.CommandContext(f.ctx, binary, append([]string{"archive", command}, args...)...)
		process.Env = environment
		if command == "verify-approval-offline" {
			process.Env = []string{"PATH=" + os.Getenv("PATH"), "REMOTE_ARCHIVE_DOMAIN_ID=" + request.DomainID}
		}
		raw, err := process.CombinedOutput()
		if success && err != nil || !success && err == nil {
			t.Fatal("production evidence archive command had unexpected result", err)
		}
		for _, private := range privateValues {
			if bytes.Contains(raw, []byte(private)) {
				t.Fatal("production evidence command exposed protected data")
			}
		}
		return raw
	}
	var summary struct {
		ExportID          string `json:"export_id"`
		State             string `json:"state"`
		Verification      string `json:"verification"`
		FingerprintSource string `json:"fingerprint_source"`
	}
	if raw := run("export-approval", arguments, true); json.Unmarshal(raw, &summary) != nil || summary.ExportID != request.ExportID || summary.State != "published" {
		t.Fatal("prepared export did not publish")
	}
	filename := request.ExportID + ".dshca"
	file := filepath.Join(directory, filename)
	body, err := os.ReadFile(file)
	if err != nil || !bytes.Equal(body, original) || bytes.Contains(body, []byte(compact)) {
		t.Fatal("retry failed to publish the original ciphertext", err)
	}
	offline := []string{"--export-id", request.ExportID, "--domain-id", request.DomainID, "--key-id", request.Key.ID(), "--key-file", keyPath, "--directory", directory}
	if raw := run("verify-approval-offline", offline, true); json.Unmarshal(raw, &summary) != nil || summary.Verification != "offline" || summary.FingerprintSource != "captured" {
		t.Fatal("offline verification scope was not reported")
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
	if raw := run("verify-approval-export", copyArgs, true); json.Unmarshal(raw, &summary) != nil || summary.Verification != "database_audited" {
		t.Fatal("copied artifact was not verified and audited")
	}
	run("export-approval", copyArgs, false)
	restoredCtx, restoredDB, restoredDSN := testsupport.RestoredPostgresDatabase(t, f.database.DB)
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
	if raw := run("verify-approval-export", restoredArgs, true); json.Unmarshal(raw, &summary) != nil || summary.Verification != "database_audited" {
		t.Fatal("copied artifact did not verify after actual recovery")
	}
	run("export-approval", restoredArgs, false)
	newID := approvalTestUUID(t)
	newArgs := append([]string(nil), restoredArgs...)
	newArgs[1] = newID
	run("export-approval", newArgs, true)
	newBody, err := os.ReadFile(filepath.Join(copyDir, newID+".dshca"))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := evidencearchive.Open(request.Key, newBody, request.DomainID, newID)
	if err != nil || payload.Proof.SourceEpoch != OriginalDatabaseEpoch || payload.OperationEpoch != epoch || len(payload.Recoveries) != 1 || payload.Recoveries[0].ID != operation {
		t.Fatal("new artifact did not retain actual recovery lineage", err)
	}
	var active, recoveredAudits int
	if err := restoredDB.QueryRowContext(restoredCtx, `select (select count(*) from runtime_grants where revoked_at is null),
	 (select count(*) from audit_log where action='approval.evidence.export.verified' and metadata->>'current_epoch'=$1)`, epoch).Scan(&active, &recoveredAudits); err != nil || active != 0 || recoveredAudits != 1 {
		t.Fatal("recovered verification revived authority or missed audit", active, recoveredAudits, err)
	}
	environment = oldEnvironment
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.DB.ExecContext(f.ctx, `create function test_fail_evidence_repair() returns trigger language plpgsql as $$
	 begin if new.action='approval.evidence.export.repair_started' then raise exception 'fixture failure'; end if; return new; end $$;
	 create trigger test_fail_evidence_repair before insert on audit_log for each row execute function test_fail_evidence_repair()`); err != nil {
		t.Fatal(err)
	}
	run("export-approval", arguments, false)
	if _, err := os.Stat(file); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("repair wrote a file before its audit intent", err)
	}
	if _, err := f.database.DB.ExecContext(f.ctx, `drop trigger test_fail_evidence_repair on audit_log; drop function test_fail_evidence_repair()`); err != nil {
		t.Fatal(err)
	}
	run("export-approval", arguments, true)
	repaired, err := os.ReadFile(file)
	if err != nil || !bytes.Equal(repaired, original) {
		t.Fatal("missing published artifact was not repaired exactly", err)
	}
	var starts, repairs, verified int
	if err := f.database.DB.QueryRowContext(f.ctx, `select count(*) filter(where action='approval.evidence.export.repair_started'),
	 count(*) filter(where action='approval.evidence.export.repaired'),count(*) filter(where action='approval.evidence.export.verified') from audit_log`).Scan(&starts, &repairs, &verified); err != nil || starts != 1 || repairs != 1 || verified != 1 {
		t.Fatal("verification or repair audit was missing", starts, repairs, verified, err)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.DB.ExecContext(f.ctx, `create function test_fail_evidence_repair() returns trigger language plpgsql as $$
	 begin if new.action='approval.evidence.export.repaired' then raise exception 'fixture failure'; end if; return new; end $$;
	 create trigger test_fail_evidence_repair before insert on audit_log for each row execute function test_fail_evidence_repair()`); err != nil {
		t.Fatal(err)
	}
	run("export-approval", arguments, false)
	if body, err := os.ReadFile(file); err != nil || !bytes.Equal(body, original) {
		t.Fatal("fixture did not reach post-publication audit failure", err)
	}
	if _, err := f.database.DB.ExecContext(f.ctx, `drop trigger test_fail_evidence_repair on audit_log; drop function test_fail_evidence_repair()`); err != nil {
		t.Fatal(err)
	}
	run("export-approval", arguments, true)
	if err := f.database.DB.QueryRowContext(f.ctx, `select count(*) filter(where action='approval.evidence.export.repair_started'),
	 count(*) filter(where action='approval.evidence.export.repaired'),count(*) filter(where action='approval.evidence.export.verified') from audit_log`).Scan(&starts, &repairs, &verified); err != nil || starts != 2 || repairs != 1 || verified != 2 {
		t.Fatal("retry did not reconcile interrupted repair audit", starts, repairs, verified, err)
	}
	repaired, err = os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	repaired[len(repaired)-1] ^= 1
	if err := os.WriteFile(file, repaired, 0600); err != nil {
		t.Fatal(err)
	}
	run("export-approval", arguments, false)
	remaining, err := os.ReadFile(file)
	if err != nil || !bytes.Equal(remaining, repaired) {
		t.Fatal("conflicting existing file was overwritten", err)
	}
	raw := run("verify-approval-offline", offline, false)
	if !strings.Contains(string(raw), "verification failed") {
		t.Fatal("tampered file did not fail verification safely")
	}
	t.Run("lost-output", func(t *testing.T) {
		full, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
		if err != nil {
			t.Skip("fixture requires /dev/full")
		}
		defer full.Close()
		newID := approvalTestUUID(t)
		newArgs := append([]string(nil), arguments...)
		newArgs[1] = newID
		process := exec.CommandContext(f.ctx, binary, append([]string{"archive", "export-approval"}, newArgs...)...)
		process.Env, process.Stdout = environment, full
		var stderr bytes.Buffer
		process.Stderr = &stderr
		if err := process.Run(); err == nil || !strings.Contains(stderr.String(), "same export UUID") {
			t.Fatal("lost output did not retain the operation identity", err)
		}
		for _, private := range privateValues {
			if strings.Contains(stderr.String(), private) {
				t.Fatal("lost-output error exposed protected data")
			}
		}
		run("export-approval", newArgs, true)
		var prepared, published int
		if err := f.database.DB.QueryRowContext(f.ctx, `select count(*) filter(where action='approval.evidence.export.prepared' and metadata->>'export_id'=$1),
		 count(*) filter(where action='approval.evidence.export.published' and metadata->>'export_id'=$1) from audit_log`, newID).Scan(&prepared, &published); err != nil || prepared != 1 || published != 1 {
			t.Fatal("lost-output retry duplicated the export", prepared, published, err)
		}
	})
}
