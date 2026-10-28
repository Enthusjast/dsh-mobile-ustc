package main

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
	"dsh-mobile-ustc/services/remote/internal/store"
	"dsh-mobile-ustc/services/remote/internal/testsupport"
)

type coldFixture struct {
	db        *store.Postgres
	request   store.ControlExportRequest
	args      []string
	directory string
	keyPath   string
}

func newColdFixture(t *testing.T) coldFixture {
	t.Helper()
	ctx, database := testsupport.PostgresDatabase(t)
	dsn := archiveTestDSN(t, ctx, database)
	t.Setenv("REMOTE_DATABASE_URL", dsn)
	t.Setenv("REMOTE_DATABASE_EPOCH", store.OriginalDatabaseEpoch)
	domain := "11111111-1111-4111-8111-111111111111"
	id := "22222222-2222-4222-8222-222222222222"
	batchID := "33333333-3333-4333-8333-333333333333"
	t.Setenv("REMOTE_ARCHIVE_DOMAIN_ID", domain)
	if _, err := database.ExecContext(ctx, `insert into control_outbox(topic,payload,created_at,published_at)
	 values('device.revoked',jsonb_build_object('device_id','dddddddd-1111-4111-8111-111111111111','marker','PRIVATE_COLD_ARCHIVE_BODY'),'2000-01-01','2000-01-02')`); err != nil {
		t.Fatal(err)
	}
	db := &store.Postgres{DB: database}
	batch, err := db.ArchiveControlEvents(ctx, store.ControlArchiveRequest{BatchID: batchID, DatabaseEpoch: store.OriginalDatabaseEpoch, Limit: 4, RetentionYears: 1})
	if err != nil || batch.Events != 1 {
		t.Fatal("archive setup", err)
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "archive.key")
	raw := bytes.Repeat([]byte{19}, 32)
	if err := os.WriteFile(keyPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	key, err := coldarchive.NewKey("fixture-key", raw)
	clear(raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Close)
	root, err := coldarchive.OpenDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := root.Fingerprint(key)
	if err != nil {
		t.Fatal(err)
	}
	_ = root.Close()
	request := store.ControlExportRequest{ExportID: id, DomainID: domain, DatabaseEpoch: store.OriginalDatabaseEpoch, BatchID: batchID, DestinationFingerprint: fingerprint, Key: key}
	args := []string{"--export-id", id, "--batch-id", batchID, "--expected-epoch", store.OriginalDatabaseEpoch, "--domain-id", domain, "--key-id", "fixture-key", "--key-file", keyPath, "--directory", directory}
	return coldFixture{db: db, request: request, args: args, directory: directory, keyPath: keyPath}
}

func TestColdArchiveCLIRecoversPreparationPublicationAndLostOutput(t *testing.T) {
	for _, scenario := range []string{"prepared-no-file", "file-before-commit", "lost-output"} {
		t.Run(scenario, func(t *testing.T) {
			f := newColdFixture(t)
			ctx := t.Context()
			var prior []byte
			if scenario != "lost-output" {
				state, artifact, err := f.db.PrepareControlExport(ctx, f.request)
				if err != nil || state.State != "prepared" {
					t.Fatal(err)
				}
				prior = append([]byte(nil), artifact...)
				if scenario == "file-before-commit" {
					root, err := coldarchive.OpenDirectory(f.directory)
					if err != nil {
						t.Fatal(err)
					}
					err = root.Publish(f.request.ExportID, artifact, func(raw []byte) error {
						_, err := coldarchive.Open(f.request.Key, raw, f.request.DomainID, f.request.ExportID)
						return err
					})
					_ = root.Close()
					if err != nil {
						t.Fatal(err)
					}
				}
			} else {
				if err := runArchiveCommand(append([]string{"export"}, f.args...), archiveFailedOutput{}); err == nil || !strings.Contains(err.Error(), "same export UUID") {
					t.Fatal("output failure did not retain reconcile identity", err)
				}
			}
			var output bytes.Buffer
			if err := runArchiveCommand(append([]string{"export"}, f.args...), &output); err != nil {
				t.Fatal("retry failed", err)
			}
			var summary coldSummary
			if json.Unmarshal(output.Bytes(), &summary) != nil || summary.State != "published" || summary.Events != 1 || summary.BatchID != f.request.BatchID {
				t.Fatal("retry did not return a verified publication")
			}
			if bytes.Contains(output.Bytes(), []byte("PRIVATE_COLD_ARCHIVE_BODY")) || bytes.Contains(output.Bytes(), []byte(f.directory)) || bytes.Contains(output.Bytes(), []byte(f.keyPath)) {
				t.Fatal("CLI output exposed source or local paths")
			}
			body, err := os.ReadFile(filepath.Join(f.directory, f.request.ExportID+".dshca"))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(body, []byte("PRIVATE_COLD_ARCHIVE_BODY")) {
				t.Fatal("artifact contains plaintext")
			}
			if prior != nil && !bytes.Equal(prior, body) {
				t.Fatal("retry changed the prepared ciphertext")
			}
			var prepared, published int
			if err := f.db.DB.QueryRowContext(ctx, `select count(*) filter(where action='control.archive.export.prepared'),count(*) filter(where action='control.archive.export.published') from audit_log`).Scan(&prepared, &published); err != nil || prepared != 1 || published != 1 {
				t.Fatal("retry duplicated durable operation audits", prepared, published, err)
			}
		})
	}
}

func TestColdArchiveCLIAuthenticatesAndAuditsOnlineOrExplicitOfflineVerification(t *testing.T) {
	f := newColdFixture(t)
	var exported bytes.Buffer
	if err := runArchiveCommand(append([]string{"export"}, f.args...), &exported); err != nil {
		t.Fatal(err)
	}
	// Copy to a different protected directory: verification is portable, while
	// an export retry itself remains bound to its original destination identity.
	copyDir := t.TempDir()
	if err := os.Chmod(copyDir, 0700); err != nil {
		t.Fatal(err)
	}
	file := f.request.ExportID + ".dshca"
	body, err := os.ReadFile(filepath.Join(f.directory, file))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(copyDir, file), body, 0600); err != nil {
		t.Fatal(err)
	}
	args := append([]string(nil), f.args...)
	args[len(args)-1] = copyDir
	var verified bytes.Buffer
	if err := runArchiveCommand(append([]string{"verify"}, args...), &verified); err != nil {
		t.Fatal(err)
	}
	var summary coldSummary
	if json.Unmarshal(verified.Bytes(), &summary) != nil || summary.Verification != "database_audited" || summary.Events != 1 {
		t.Fatal("online verification did not report audited result")
	}
	var audited int
	if err := f.db.DB.QueryRowContext(t.Context(), `select count(*) from audit_log where action='control.archive.export.verified' and metadata ? 'access_location_fingerprint'`).Scan(&audited); err != nil || audited != 1 {
		t.Fatal("verified read was not audited", audited, err)
	}
	if err := runArchiveCommand(append([]string{"export"}, args...), &bytes.Buffer{}); !errors.Is(err, store.ErrControlExportConflict) {
		t.Fatal("export operation silently rebound its destination", err)
	}
	offline := []string{"verify-offline", "--export-id", f.request.ExportID, "--domain-id", f.request.DomainID, "--key-id", "fixture-key", "--key-file", f.keyPath, "--directory", copyDir}
	var checked bytes.Buffer
	if err := runArchiveCommand(offline, &checked); err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(checked.Bytes(), &summary) != nil || summary.Verification != "offline" {
		t.Fatal("offline scope was not distinguished")
	}
	body[len(body)-1] ^= 1
	if err := os.WriteFile(filepath.Join(copyDir, file), body, 0600); err != nil {
		t.Fatal(err)
	}
	if err := runArchiveCommand(offline, &bytes.Buffer{}); err == nil {
		t.Fatal("tampered file verified")
	}
}

func TestColdArchiveCLIRequiresExplicitTrustedDomainAndProtectedKey(t *testing.T) {
	f := newColdFixture(t)
	t.Setenv("REMOTE_ARCHIVE_DOMAIN_ID", "44444444-4444-4444-8444-444444444444")
	if err := runArchiveCommand(append([]string{"export"}, f.args...), &bytes.Buffer{}); err == nil {
		t.Fatal("unmatched external domain accepted")
	}
	t.Setenv("REMOTE_ARCHIVE_DOMAIN_ID", f.request.DomainID)
	if err := os.Chmod(f.keyPath, 0644); err != nil {
		t.Fatal(err)
	}
	if err := runArchiveCommand(append([]string{"export"}, f.args...), &bytes.Buffer{}); err == nil {
		t.Fatal("public key file accepted")
	}
	var count int
	if err := f.db.DB.QueryRowContext(t.Context(), `select count(*) from control_archive_exports`).Scan(&count); err != nil || count != 0 {
		t.Fatal("invalid input changed database state", count, err)
	}
}

func TestColdArchiveCLIRepairsMissingPublishedFileButNeverOverwritesTampering(t *testing.T) {
	f := newColdFixture(t)
	if err := runArchiveCommand(append([]string{"export"}, f.args...), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.directory, f.request.ExportID+".dshca")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := runArchiveCommand(append([]string{"export"}, f.args...), &bytes.Buffer{}); err != nil {
		t.Fatal("missing published file could not be repaired", err)
	}
	repaired, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(original, repaired) {
		t.Fatal("repair did not reproduce the original authenticated file", err)
	}
	var starts, repairs int
	if err := f.db.DB.QueryRowContext(t.Context(), `select count(*) filter(where action='control.archive.export.repair_started'),count(*) filter(where action='control.archive.export.repaired') from audit_log`).Scan(&starts, &repairs); err != nil || starts != 1 || repairs != 1 {
		t.Fatal("repair intent or completion was not audited", starts, repairs, err)
	}
	repaired[len(repaired)-1] ^= 1
	if err := os.WriteFile(path, repaired, 0600); err != nil {
		t.Fatal(err)
	}
	if err := runArchiveCommand(append([]string{"export"}, f.args...), &bytes.Buffer{}); err == nil {
		t.Fatal("tampered existing file was accepted")
	}
	remaining, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(remaining, repaired) {
		t.Fatal("tampered existing file was overwritten", err)
	}
	if err := f.db.DB.QueryRowContext(t.Context(), `select count(*) from audit_log where action='control.archive.export.repaired'`).Scan(&repairs); err != nil || repairs != 1 {
		t.Fatal("failed retry changed the repair audit", repairs, err)
	}
}

func TestColdArchiveRepairAuditFailureCanBeReconciled(t *testing.T) {
	for _, action := range []string{"repair_started", "repaired"} {
		t.Run(action, func(t *testing.T) {
			f := newColdFixture(t)
			if err := runArchiveCommand(append([]string{"export"}, f.args...), &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(f.directory, f.request.ExportID+".dshca")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			// A local fixture simulates an unavailable audit sink at either side
			// of filesystem publication, without changing production tables.
			if _, err := f.db.DB.ExecContext(t.Context(), `create function test_reject_repair_audit() returns trigger language plpgsql as $$
			 begin if new.action='control.archive.export.`+action+`' then raise exception 'fixture audit failure'; end if; return new; end $$;
			 create trigger test_reject_repair_audit before insert on audit_log for each row execute function test_reject_repair_audit()`); err != nil {
				t.Fatal(err)
			}
			if err := runArchiveCommand(append([]string{"export"}, f.args...), &bytes.Buffer{}); err == nil {
				t.Fatal("repair ignored an audit failure")
			}
			_, statErr := os.Stat(path)
			if action == "repair_started" && !errors.Is(statErr, os.ErrNotExist) {
				t.Fatal("file was written before repair intent was audited", statErr)
			}
			if action == "repaired" && statErr != nil {
				t.Fatal("fixture did not reach post-publication failure", statErr)
			}
			if _, err := f.db.DB.ExecContext(t.Context(), `drop trigger test_reject_repair_audit on audit_log; drop function test_reject_repair_audit()`); err != nil {
				t.Fatal(err)
			}
			if err := runArchiveCommand(append([]string{"export"}, f.args...), &bytes.Buffer{}); err != nil {
				t.Fatal("repair retry could not reconcile", err)
			}
			var starts, completed, verified int
			if err := f.db.DB.QueryRowContext(t.Context(), `select count(*) filter(where action='control.archive.export.repair_started'),count(*) filter(where action='control.archive.export.repaired'),count(*) filter(where action='control.archive.export.verified') from audit_log`).Scan(&starts, &completed, &verified); err != nil || starts != 1 {
				t.Fatal("repair intent was not durably recorded", starts, completed, verified, err)
			}
			if action == "repair_started" && (completed != 1 || verified != 0) || action == "repaired" && (completed != 0 || verified != 1) {
				t.Fatal("retry did not record the correct reconciliation", completed, verified)
			}
		})
	}
}

func TestColdArchiveProductionBinaryExportAndOfflineVerification(t *testing.T) {
	binary := os.Getenv("REMOTE_TEST_SERVICE_BIN")
	if binary == "" {
		t.Skip("explicit disposable production service binary required")
	}
	f := newColdFixture(t)
	run := func(args []string) coldSummary {
		t.Helper()
		command := exec.CommandContext(t.Context(), binary, append([]string{"archive"}, args...)...)
		command.Env = []string{"PATH=" + os.Getenv("PATH"), "REMOTE_DATABASE_URL=" + os.Getenv("REMOTE_DATABASE_URL"), "REMOTE_DATABASE_EPOCH=" + store.OriginalDatabaseEpoch, "REMOTE_ARCHIVE_DOMAIN_ID=" + f.request.DomainID}
		raw, err := command.CombinedOutput()
		if err != nil {
			t.Fatal("production archive command failed", err)
		}
		for _, private := range []string{"PRIVATE_COLD_ARCHIVE_BODY", f.directory, f.keyPath, os.Getenv("REMOTE_DATABASE_URL"), string(bytes.Repeat([]byte{19}, 32))} {
			if bytes.Contains(raw, []byte(private)) {
				t.Fatal("production command exposed protected data")
			}
		}
		var result coldSummary
		if json.Unmarshal(raw, &result) != nil || result.ExportID != f.request.ExportID || result.Events != 1 {
			t.Fatal("production command returned invalid summary")
		}
		return result
	}
	if result := run(append([]string{"export"}, f.args...)); result.State != "published" {
		t.Fatal("production export did not publish")
	}
	offline := []string{"verify-offline", "--export-id", f.request.ExportID, "--domain-id", f.request.DomainID, "--key-id", "fixture-key", "--key-file", f.keyPath, "--directory", f.directory}
	if result := run(offline); result.Verification != "offline" {
		t.Fatal("production offline verification returned the wrong scope")
	}
}

func TestColdArchiveCLIVerifiesCopiedFileAfterActualRestoreAndExportsOldBatch(t *testing.T) {
	f := newColdFixture(t)
	if err := runArchiveCommand(append([]string{"export"}, f.args...), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	ctx, database, dsn := testsupport.RestoredPostgresDatabase(t, f.db.DB)
	restored := &store.Postgres{DB: database}
	epoch, operation := "44444444-4444-4444-8444-444444444444", "55555555-5555-4555-8555-555555555555"
	if _, err := restored.QuarantineRecovery(ctx, operation, store.OriginalDatabaseEpoch, epoch); err != nil {
		t.Fatal(err)
	}
	manifest := store.RecoveryAuthority{Version: 1, Complete: true, RecoveryID: operation, DatabaseEpoch: epoch, Issuer: "https://id.example.edu", CapturedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Minute).UTC(), Users: []store.RecoveryUser{}}
	if _, err := restored.ReleaseRecovery(ctx, epoch, manifest.Issuer, manifest); err != nil {
		t.Fatal(err)
	}
	copyDir := t.TempDir()
	if err := os.Chmod(copyDir, 0700); err != nil {
		t.Fatal(err)
	}
	filename := f.request.ExportID + ".dshca"
	body, err := os.ReadFile(filepath.Join(f.directory, filename))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(copyDir, filename), body, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REMOTE_DATABASE_URL", dsn)
	t.Setenv("REMOTE_DATABASE_EPOCH", epoch)
	args := append([]string(nil), f.args...)
	args[5], args[len(args)-1] = epoch, copyDir
	var verified bytes.Buffer
	if err := runArchiveCommand(append([]string{"verify"}, args...), &verified); err != nil {
		t.Fatal("copied artifact was not verifiable in the released epoch", err)
	}
	var summary coldSummary
	if json.Unmarshal(verified.Bytes(), &summary) != nil || summary.Verification != "database_audited" || summary.OperationEpoch != store.OriginalDatabaseEpoch {
		t.Fatal("recovered verification lost its original epoch")
	}
	var count int
	if err := database.QueryRowContext(ctx, `select count(*) from audit_log where action='control.archive.export.verified' and metadata->>'current_epoch'=$1`, epoch).Scan(&count); err != nil || count != 1 {
		t.Fatal("recovered verification was not audited", count, err)
	}
	if err := runArchiveCommand(append([]string{"export"}, args...), &bytes.Buffer{}); !errors.Is(err, store.ErrControlExportConflict) {
		t.Fatal("old export was rebound after recovery", err)
	}
	newID := "66666666-6666-4666-8666-666666666666"
	args[1] = newID
	if err := runArchiveCommand(append([]string{"export"}, args...), &bytes.Buffer{}); err != nil {
		t.Fatal("old batch could not be freshly exported in released epoch", err)
	}
	newBody, err := os.ReadFile(filepath.Join(copyDir, newID+".dshca"))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := coldarchive.Open(f.request.Key, newBody, f.request.DomainID, newID)
	if err != nil || payload.Batch.DatabaseEpoch != store.OriginalDatabaseEpoch || payload.OperationEpoch != epoch || len(payload.Recoveries) != 1 || payload.Recoveries[0].ID != operation {
		t.Fatal("fresh export lost released recovery lineage", err)
	}
}
