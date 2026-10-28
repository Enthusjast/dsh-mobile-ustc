package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"dsh-mobile-ustc/services/remote/internal/store"
	"dsh-mobile-ustc/services/remote/internal/testsupport"
)

func TestColdImportProductionBinaryReconcilesLostOutputIntoSeparateHistory(t *testing.T) {
	binary := os.Getenv("REMOTE_TEST_SERVICE_BIN")
	if binary == "" {
		t.Skip("explicit disposable production service binary required")
	}
	f := newColdFixture(t)
	if err := runArchiveCommand(append([]string{"export"}, f.args...), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	ctx, target := testsupport.PostgresDatabase(t)
	dsn := archiveTestDSN(t, ctx, target)
	t.Setenv("REMOTE_DATABASE_URL", dsn)
	importID := "77777777-7777-4777-8777-777777777777"
	args := []string{"import", "--import-id", importID, "--export-id", f.request.ExportID, "--domain-id", f.request.DomainID,
		"--expected-epoch", store.OriginalDatabaseEpoch, "--key-id", "fixture-key", "--key-file", f.keyPath, "--directory", f.directory}
	if err := runArchiveCommand(args, archiveFailedOutput{}); err == nil || !strings.Contains(err.Error(), "same import UUID") || strings.Contains(err.Error(), "PRIVATE_OUTPUT_ERROR") {
		t.Fatal("output loss did not preserve import identity", err)
	}
	command := exec.CommandContext(ctx, binary, append([]string{"archive"}, args...)...)
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "REMOTE_DATABASE_URL=" + dsn, "REMOTE_DATABASE_EPOCH=" + store.OriginalDatabaseEpoch, "REMOTE_ARCHIVE_DOMAIN_ID=" + f.request.DomainID}
	raw, err := command.CombinedOutput()
	if err != nil {
		t.Fatal("production import retry failed", err)
	}
	var result store.ControlImportResult
	if json.Unmarshal(raw, &result) != nil || result.ImportID != importID || result.ExportID != f.request.ExportID || result.Events != 1 {
		t.Fatal("production import did not return the original result")
	}
	for _, private := range []string{"PRIVATE_COLD_ARCHIVE_BODY", f.keyPath, f.directory, dsn, string(bytes.Repeat([]byte{19}, 32))} {
		if bytes.Contains(raw, []byte(private)) {
			t.Fatal("production import exposed protected content")
		}
	}
	var histories, imported, verified, outbox, grants, recoveries int
	if err := target.QueryRowContext(ctx, `select (select count(*) from control_archive_import_payloads),
	 (select count(*) from audit_log where action='control.archive.import'),(select count(*) from audit_log where action='control.archive.import.verified'),
	 (select count(*) from control_outbox),(select count(*) from runtime_grants),(select count(*) from remote_recovery_runs)`).
		Scan(&histories, &imported, &verified, &outbox, &grants, &recoveries); err != nil || histories != 1 || imported != 1 || verified != 1 || outbox != 0 || grants != 0 || recoveries != 0 {
		t.Fatal("production import changed live state or duplicated history", histories, imported, verified, outbox, grants, recoveries, err)
	}
}

func TestColdImportCLIRejectsDomainAndTamperingBeforeChangingDatabase(t *testing.T) {
	f := newColdFixture(t)
	if err := runArchiveCommand(append([]string{"export"}, f.args...), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	args := []string{"import", "--import-id", "77777777-7777-4777-8777-777777777777", "--export-id", f.request.ExportID,
		"--domain-id", f.request.DomainID, "--expected-epoch", store.OriginalDatabaseEpoch, "--key-id", "fixture-key", "--key-file", f.keyPath, "--directory", f.directory}
	t.Setenv("REMOTE_ARCHIVE_DOMAIN_ID", "88888888-8888-4888-8888-888888888888")
	if err := runArchiveCommand(args, &bytes.Buffer{}); err == nil {
		t.Fatal("external domain mismatch was accepted")
	}
	t.Setenv("REMOTE_ARCHIVE_DOMAIN_ID", f.request.DomainID)
	path := filepath.Join(f.directory, f.request.ExportID+".dshca")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body[len(body)-1] ^= 1
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	if err := runArchiveCommand(args, &bytes.Buffer{}); err == nil {
		t.Fatal("modified artifact was accepted")
	}
	var count int
	if err := f.db.DB.QueryRowContext(t.Context(), `select count(*) from control_archive_imports`).Scan(&count); err != nil || count != 0 {
		t.Fatal("invalid input changed history", count, err)
	}
}
