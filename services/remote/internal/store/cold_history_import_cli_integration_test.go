package store

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestColdHistoryImportProductionBinaryReconcilesAndKeepsHistoryInert(t *testing.T) {
	binary := os.Getenv("REMOTE_TEST_SERVICE_BIN")
	if binary == "" {
		t.Skip("explicit disposable production service binary required")
	}
	for _, kind := range []string{"audit", "approval"} {
		t.Run(kind, func(t *testing.T) {
			ctx, target, request, artifact, source := coldHistoryFixture(t, kind, false)
			directory := t.TempDir()
			if err := os.Chmod(directory, 0700); err != nil {
				t.Fatal(err)
			}
			keyPath := filepath.Join(t.TempDir(), "history.key")
			keyByte := byte(51)
			if kind == "approval" {
				keyByte = 42
			}
			if err := os.WriteFile(keyPath, bytes.Repeat([]byte{keyByte}, 32), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(directory, request.ExportID+".dshca"), artifact, 0600); err != nil {
				t.Fatal(err)
			}
			dsn := auditColdFixtureDSN(t, ctx, target.DB)
			environment := []string{"PATH=" + os.Getenv("PATH"), "REMOTE_DATABASE_URL=" + dsn, "REMOTE_DATABASE_EPOCH=" + request.DatabaseEpoch, "REMOTE_ARCHIVE_DOMAIN_ID=" + request.DomainID}
			arguments := []string{"--import-id", request.ImportID, "--export-id", request.ExportID, "--domain-id", request.DomainID,
				"--expected-epoch", request.DatabaseEpoch, "--key-id", request.Key.ID(), "--key-file", keyPath, "--directory", directory}
			private := []string{source, "PRIVATE_AUDIT_COLD_BODY", directory, keyPath, dsn}
			checkPrivate := func(raw []byte) {
				t.Helper()
				for _, value := range private {
					if value != "" && bytes.Contains(raw, []byte(value)) {
						t.Fatal("history import exposed protected data")
					}
				}
			}
			if full, err := os.OpenFile("/dev/full", os.O_WRONLY, 0); err == nil {
				process := exec.CommandContext(ctx, binary, append([]string{"archive", "import-" + kind}, arguments...)...)
				process.Env, process.Stdout = environment, full
				var stderr bytes.Buffer
				process.Stderr = &stderr
				runErr := process.Run()
				_ = full.Close()
				if runErr == nil || !strings.Contains(stderr.String(), "same import UUID") {
					t.Fatal("lost output did not preserve the import identity", runErr)
				}
				checkPrivate(stderr.Bytes())
			} else {
				t.Log("/dev/full unavailable; lost-output injection omitted")
			}
			process := exec.CommandContext(ctx, binary, append([]string{"archive", "import-" + kind}, arguments...)...)
			process.Env = environment
			raw, err := process.CombinedOutput()
			if err != nil {
				t.Fatal("production history import retry failed", err)
			}
			checkPrivate(raw)
			var result ColdHistoryImportResult
			if json.Unmarshal(raw, &result) != nil || result.Kind != kind || result.ImportID != request.ImportID || result.ExportID != request.ExportID || result.Entries != 1 {
				t.Fatal("production history import returned an invalid result")
			}
			wrongKind := "audit"
			if kind == "audit" {
				wrongKind = "approval"
			}
			process = exec.CommandContext(ctx, binary, append([]string{"archive", "import-" + wrongKind}, arguments...)...)
			process.Env = environment
			raw, err = process.CombinedOutput()
			if err == nil {
				t.Fatal("production importer accepted another archive type")
			}
			checkPrivate(raw)
			var histories, imports, approvals, activeEvents, sourceAudits int
			if err := target.DB.QueryRowContext(ctx, `select (select count(*) from cold_history_import_payloads),
			 (select count(*) from audit_log where action='cold.history.import'),(select count(*) from approvals),
			 (select count(*) from control_outbox),(select count(*) from audit_log where action='fixture.event')`).
				Scan(&histories, &imports, &approvals, &activeEvents, &sourceAudits); err != nil || histories != 1 || imports != 1 || approvals != 0 || activeEvents != 0 || sourceAudits != 0 {
				t.Fatal("production import changed live state or duplicated history", histories, imports, approvals, activeEvents, sourceAudits, err)
			}
		})
	}
}
