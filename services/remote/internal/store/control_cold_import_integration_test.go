package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/coldarchive"
	"dsh-mobile-ustc/services/remote/internal/testsupport"
)

func controlImportFixture(t *testing.T, expired bool) (context.Context, *Postgres, ControlImportRequest, []byte) {
	t.Helper()
	ctx, source := newPostgresIntegrationDatabase(t)
	var batch ControlArchiveResult
	if expired {
		batch = expiredArchive(t, ctx, source)
	} else {
		batch = populatedArchive(t, ctx, source)
	}
	key := exportFixtureKey(t, 31)
	export := exportFixtureRequest(t, batch.BatchID, key)
	_, artifact, err := source.PrepareControlExport(ctx, export)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(artifact) })
	targetCtx, target := newPostgresIntegrationDatabase(t)
	request := ControlImportRequest{ImportID: approvalTestUUID(t), ExportID: export.ExportID, DomainID: export.DomainID, DatabaseEpoch: OriginalDatabaseEpoch, AccessFingerprint: strings.Repeat("b", 64), Key: key}
	return targetCtx, target, request, artifact
}

func TestControlColdImportPreservesHistoryWithoutRestoringLiveAuthority(t *testing.T) {
	ctx, target, request, artifact := controlImportFixture(t, false)
	seedGrantFixture(t, ctx, target.DB)
	live := archiveFixtureEvent(t, ctx, target.DB, "device.revoked", "2000-01-01T00:00:00Z", "")
	var before string
	if err := target.DB.QueryRowContext(ctx, `select to_jsonb(g)::text from runtime_grants g where revoked_at is null limit 1`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	result, err := target.ImportControlHistory(ctx, request, artifact)
	if err != nil || result.ImportID != request.ImportID || result.Events != 1 || result.Acknowledgements != 1 {
		t.Fatal("history import failed", err)
	}
	payload, err := coldarchive.Open(request.Key, artifact, request.DomainID, request.ExportID)
	if err != nil {
		t.Fatal(err)
	}
	var sourceEqual bool
	if err := target.DB.QueryRowContext(ctx, `select payload->'events'->0->'source'=$2::jsonb from control_archive_import_payloads where import_id=$1`, request.ImportID, string(payload.Events[0].Source)).Scan(&sourceEqual); err != nil || !sourceEqual {
		t.Fatal("import did not preserve source history", err)
	}
	var after string
	var outbox, importedEvent, acknowledgements, batches, recoveries int
	if err := target.DB.QueryRowContext(ctx, `select (select to_jsonb(g)::text from runtime_grants g where revoked_at is null limit 1),
	 (select count(*) from control_outbox where id=$1), (select count(*) from control_outbox where id=$2),
	 (select count(*) from control_event_acks), (select count(*) from control_archive_batches), (select count(*) from remote_recovery_runs)`, live, payload.Events[0].ID).
		Scan(&after, &outbox, &importedEvent, &acknowledgements, &batches, &recoveries); err != nil || after != before || outbox != 1 || importedEvent != 0 || acknowledgements != 0 || batches != 0 || recoveries != 0 {
		t.Fatal("history import changed live state", outbox, importedEvent, acknowledgements, batches, recoveries, err)
	}
	retry, err := target.ImportControlHistory(ctx, request, artifact)
	if err != nil || !retry.ImportedAt.Equal(result.ImportedAt) || retry.ArtifactSHA256 != result.ArtifactSHA256 {
		t.Fatal("import retry was not stable", err)
	}
	var imported, verified int
	if err := target.DB.QueryRowContext(ctx, `select count(*) filter(where action='control.archive.import'),count(*) filter(where action='control.archive.import.verified') from audit_log`).Scan(&imported, &verified); err != nil || imported != 1 || verified != 1 {
		t.Fatal("import and retry were not audited", imported, verified, err)
	}
	for _, statement := range []string{
		`update control_archive_import_payloads set payload='{}'::jsonb`,
		`delete from control_archive_import_payloads`,
		`delete from control_archive_imports`,
		`truncate control_archive_import_payloads`,
	} {
		if _, err := target.DB.ExecContext(ctx, statement); err == nil {
			t.Fatal("unexpired imported history was changed")
		}
	}
}

func TestControlColdImportRejectsWrongFileIdentityAndAuditFailure(t *testing.T) {
	ctx, target, request, artifact := controlImportFixture(t, false)
	modified := append([]byte(nil), artifact...)
	modified[len(modified)-1] ^= 1
	if _, err := target.ImportControlHistory(ctx, request, modified); !errors.Is(err, ErrControlImportInvalid) {
		t.Fatal("tampered artifact accepted", err)
	}
	wrong := request
	wrong.Key = exportFixtureKey(t, 32)
	if _, err := target.ImportControlHistory(ctx, wrong, artifact); !errors.Is(err, ErrControlImportInvalid) {
		t.Fatal("wrong key accepted", err)
	}
	wrong = request
	wrong.DomainID = approvalTestUUID(t)
	if _, err := target.ImportControlHistory(ctx, wrong, artifact); !errors.Is(err, ErrControlImportInvalid) {
		t.Fatal("wrong domain accepted", err)
	}
	if _, err := target.DB.ExecContext(ctx, `create function test_fail_import_audit() returns trigger language plpgsql as $$
	 begin if new.action='control.archive.import' then raise exception 'fixture audit failure'; end if; return new; end $$;
	 create trigger test_fail_import_audit before insert on audit_log for each row execute function test_fail_import_audit()`); err != nil {
		t.Fatal(err)
	}
	if _, err := target.ImportControlHistory(ctx, request, artifact); !errors.Is(err, ErrDatabaseUnavailable) {
		t.Fatal("import ignored audit failure", err)
	}
	var headers, payloads int
	if err := target.DB.QueryRowContext(ctx, `select (select count(*) from control_archive_imports),(select count(*) from control_archive_import_payloads)`).Scan(&headers, &payloads); err != nil || headers != 0 || payloads != 0 {
		t.Fatal("audit failure left partial import", headers, payloads, err)
	}
	if _, err := target.DB.ExecContext(ctx, `drop trigger test_fail_import_audit on audit_log; drop function test_fail_import_audit()`); err != nil {
		t.Fatal(err)
	}
	if _, err := target.ImportControlHistory(ctx, request, artifact); err != nil {
		t.Fatal(err)
	}
	wrong = request
	wrong.ImportID = approvalTestUUID(t)
	if _, err := target.ImportControlHistory(ctx, wrong, artifact); !errors.Is(err, ErrControlImportConflict) {
		t.Fatal("same export was claimed by a second import", err)
	}
}

func TestControlColdImportConcurrentRetriesShareOneIdentity(t *testing.T) {
	ctx, target, request, artifact := controlImportFixture(t, false)
	type outcome struct {
		result ControlImportResult
		err    error
	}
	results := make(chan outcome, 4)
	var group sync.WaitGroup
	for range 4 {
		group.Go(func() {
			result, err := target.ImportControlHistory(ctx, request, artifact)
			results <- outcome{result, err}
		})
	}
	group.Wait()
	close(results)
	var first ControlImportResult
	for item := range results {
		if item.err != nil {
			t.Fatal(item.err)
		}
		if first.ImportID == "" {
			first = item.result
		} else if !first.ImportedAt.Equal(item.result.ImportedAt) || first.ArtifactSHA256 != item.result.ArtifactSHA256 {
			t.Fatal("concurrent retry changed import identity")
		}
	}
	var headers, payloads, audits int
	if err := target.DB.QueryRowContext(ctx, `select (select count(*) from control_archive_imports),(select count(*) from control_archive_import_payloads),(select count(*) from audit_log where action='control.archive.import')`).Scan(&headers, &payloads, &audits); err != nil || headers != 1 || payloads != 1 || audits != 1 {
		t.Fatal("concurrent import was duplicated", headers, payloads, audits, err)
	}
}

func TestControlColdImportRejectsCorruptedOrIncompleteStoredHistory(t *testing.T) {
	ctx, target, request, artifact := controlImportFixture(t, false)
	if _, err := target.ImportControlHistory(ctx, request, artifact); err != nil {
		t.Fatal(err)
	}
	if _, err := target.DB.ExecContext(ctx, `insert into control_archive_imports(id,domain_id,export_id,batch_id,batch_epoch,source_epoch,target_epoch,key_id,key_fingerprint,
	 artifact_sha256,artifact_size,payload_sha256,event_count,acknowledgement_count,retain_until,imported_at)
	 select $1,domain_id,$2,batch_id,batch_epoch,source_epoch,target_epoch,key_id,key_fingerprint,artifact_sha256,artifact_size,payload_sha256,event_count,acknowledgement_count,retain_until,clock_timestamp()
	 from control_archive_imports where id=$3`, approvalTestUUID(t), approvalTestUUID(t), request.ImportID); err == nil {
		t.Fatal("an import identity committed without its payload")
	}
	// Simulate corruption by a privileged database actor; ordinary UPDATE is denied.
	tx, err := target.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `alter table control_archive_import_payloads disable trigger control_archive_import_payload_guard`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `update control_archive_import_payloads set payload=jsonb_set(payload,'{events,0,source,payload,marker}','"corrupted"'::jsonb) where import_id=$1`, request.ImportID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `alter table control_archive_import_payloads enable trigger control_archive_import_payload_guard`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := target.ImportControlHistory(ctx, request, artifact); !errors.Is(err, ErrControlImportConflict) {
		t.Fatal("retry accepted corrupted stored history", err)
	}
}

func TestControlColdImportHistoryRequiresExplicitPrivileges(t *testing.T) {
	ctx, target, request, artifact := controlImportFixture(t, false)
	if _, err := target.ImportControlHistory(ctx, request, artifact); err != nil {
		t.Fatal(err)
	}
	role := "dsh_cold_import_" + strings.ReplaceAll(approvalTestUUID(t), "-", "")
	if _, err := target.DB.ExecContext(ctx, "create role "+role+" nologin"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := target.DB.ExecContext(cleanup, "drop role "+role); err != nil {
			t.Error("fixture role was not removed", err)
		}
	})
	var metadataRead, payloadRead, payloadWrite bool
	if err := target.DB.QueryRowContext(ctx, `select has_table_privilege($1,'control_archive_imports','select'),
	 has_table_privilege($1,'control_archive_import_payloads','select'),has_table_privilege($1,'control_archive_import_payloads','insert')`, role).
		Scan(&metadataRead, &payloadRead, &payloadWrite); err != nil || metadataRead || payloadRead || payloadWrite {
		t.Fatal("imported history was exposed without an explicit grant", metadataRead, payloadRead, payloadWrite, err)
	}
}

func TestControlColdImportExpiredDeletionCannotResurrectOrRollbackHistory(t *testing.T) {
	ctx, target, request, artifact := controlImportFixture(t, true)
	if _, err := target.ImportControlHistory(ctx, request, artifact); err != nil {
		t.Fatal(err)
	}
	var payload string
	if err := target.DB.QueryRowContext(ctx, `select payload::text from control_archive_import_payloads where import_id=$1`, request.ImportID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if _, err := target.DB.ExecContext(ctx, `delete from control_archive_import_payloads where import_id=$1`, request.ImportID); err != nil {
		t.Fatal("expired history could not be deleted", err)
	}
	if _, err := target.ImportControlHistory(ctx, request, artifact); !errors.Is(err, ErrControlImportExpired) {
		t.Fatal("retry resurrected deleted history", err)
	}
	other := request
	other.ImportID = approvalTestUUID(t)
	if _, err := target.ImportControlHistory(ctx, other, artifact); !errors.Is(err, ErrControlImportConflict) {
		t.Fatal("new operation resurrected deleted history", err)
	}
	if _, err := target.DB.ExecContext(ctx, `insert into control_archive_import_payloads(import_id,payload) values($1,$2::jsonb)`, request.ImportID, payload); err == nil {
		t.Fatal("direct insertion resurrected deleted history")
	}
	var removed, retained int
	if err := target.DB.QueryRowContext(ctx, `select (select count(*) from audit_log where action='control.archive.import.delete'),(select count(*) from control_archive_imports)`).Scan(&removed, &retained); err != nil || removed != 1 || retained != 1 {
		t.Fatal("expiry lost audit or identity", removed, retained, err)
	}
	down, err := os.ReadFile("../../../../deploy/sql/024_control_cold_imports.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := target.DB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, string(down)); err == nil {
		t.Fatal("migration removed retained import identity")
	}
	if _, err := conn.ExecContext(ctx, `rollback`); err != nil {
		t.Fatal(err)
	}
}

func TestControlColdImportRetrySerializesWithExpiryDeletion(t *testing.T) {
	ctx, target, request, artifact := controlImportFixture(t, true)
	target.DB.SetMaxOpenConns(5)
	if _, err := target.ImportControlHistory(ctx, request, artifact); err != nil {
		t.Fatal(err)
	}
	if _, err := target.DB.ExecContext(ctx, `create function test_hold_import_audit() returns trigger language plpgsql as $$
	 begin if new.action='control.archive.import.verified' then perform pg_advisory_xact_lock(763202); end if; return new; end $$;
	 create trigger test_hold_import_audit before insert on audit_log for each row execute function test_hold_import_audit()`); err != nil {
		t.Fatal(err)
	}
	holder, err := target.DB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if _, err := holder.ExecContext(ctx, `select pg_advisory_lock(763202)`); err != nil {
		t.Fatal(err)
	}
	defer holder.ExecContext(context.Background(), `select pg_advisory_unlock(763202)`)
	verified := make(chan error, 1)
	go func() {
		_, err := target.ImportControlHistory(ctx, request, artifact)
		verified <- err
	}()
	waitForLock := func(pattern string) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for {
			var waiting bool
			if err := target.DB.QueryRowContext(ctx, `select exists(select 1 from pg_stat_activity where datname=current_database() and wait_event_type='Lock' and query like $1)`, pattern).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if waiting {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("fixture did not reach the expected database lock")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	waitForLock("insert into audit_log%")
	deleted := make(chan error, 1)
	go func() {
		_, err := target.DB.ExecContext(ctx, `delete from control_archive_import_payloads where import_id=$1 /* import-expiry-race */`, request.ImportID)
		deleted <- err
	}()
	waitForLock("delete from control_archive_import_payloads%import-expiry-race%")
	if _, err := holder.ExecContext(ctx, `select pg_advisory_unlock(763202)`); err != nil {
		t.Fatal(err)
	}
	if err := <-verified; err != nil {
		t.Fatal("verified retry did not commit before expiry", err)
	}
	if err := <-deleted; err != nil {
		t.Fatal("expiry did not proceed after retry committed", err)
	}
	if _, err := target.ImportControlHistory(ctx, request, artifact); !errors.Is(err, ErrControlImportExpired) {
		t.Fatal("subsequent retry missed deletion", err)
	}
}

func TestControlColdImportAfterActualRestoreDoesNotReviveOldGrants(t *testing.T) {
	ctx, target, request, artifact := controlImportFixture(t, false)
	seedGrantFixture(t, ctx, target.DB)
	restoredCtx, database, _ := testsupport.RestoredPostgresDatabase(t, target.DB)
	restored := &Postgres{DB: database}
	epoch, operation := approvalTestUUID(t), approvalTestUUID(t)
	if _, err := restored.QuarantineRecovery(restoredCtx, operation, OriginalDatabaseEpoch, epoch); err != nil {
		t.Fatal(err)
	}
	manifest := RecoveryAuthority{Version: 1, Complete: true, RecoveryID: operation, DatabaseEpoch: epoch, Issuer: "https://id.example.edu", CapturedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Minute).UTC(), Users: []RecoveryUser{}}
	if _, err := restored.ReleaseRecovery(restoredCtx, epoch, manifest.Issuer, manifest); err != nil {
		t.Fatal(err)
	}
	request.DatabaseEpoch = epoch
	result, err := restored.ImportControlHistory(restoredCtx, request, artifact)
	if err != nil || result.TargetEpoch != epoch || result.SourceEpoch != OriginalDatabaseEpoch {
		t.Fatal("history could not be imported into released recovery", err)
	}
	var activeGrants, liveEvents, liveAcks, histories int
	if err := database.QueryRowContext(restoredCtx, `select (select count(*) from runtime_grants where revoked_at is null),
	 (select count(*) from control_outbox), (select count(*) from control_event_acks), (select count(*) from control_archive_import_payloads)`).Scan(&activeGrants, &liveEvents, &liveAcks, &histories); err != nil || activeGrants != 0 || liveEvents != 0 || liveAcks != 0 || histories != 1 {
		t.Fatal("history import revived live state", activeGrants, liveEvents, liveAcks, histories, err)
	}
	// Changing only the target epoch cannot rebind this operation.
	request.DatabaseEpoch = OriginalDatabaseEpoch
	if _, err := restored.ImportControlHistory(restoredCtx, request, artifact); !errors.Is(err, ErrRecoveryUnavailable) {
		t.Fatal("old target epoch was accepted", err)
	}
	if bytes.Contains(artifact, []byte(controlDevice)) {
		t.Fatal("fixture artifact exposed source metadata")
	}
	nextEpoch, nextOperation := approvalTestUUID(t), approvalTestUUID(t)
	if _, err := restored.QuarantineRecovery(restoredCtx, nextOperation, epoch, nextEpoch); err != nil {
		t.Fatal(err)
	}
	nextManifest := RecoveryAuthority{Version: 1, Complete: true, RecoveryID: nextOperation, DatabaseEpoch: nextEpoch, Issuer: manifest.Issuer, CapturedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Minute).UTC(), Users: []RecoveryUser{}}
	if _, err := restored.ReleaseRecovery(restoredCtx, nextEpoch, nextManifest.Issuer, nextManifest); err != nil {
		t.Fatal(err)
	}
	request.DatabaseEpoch = nextEpoch
	if _, err := restored.ImportControlHistory(restoredCtx, request, artifact); !errors.Is(err, ErrControlImportConflict) {
		t.Fatal("completed import was rebound to a later recovery epoch", err)
	}
	if err := database.QueryRowContext(restoredCtx, `select count(*) from control_archive_import_payloads`).Scan(&histories); err != nil || histories != 1 {
		t.Fatal("recovery lost imported history", histories, err)
	}
}
