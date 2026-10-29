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

	"dsh-mobile-ustc/services/remote/internal/auditarchive"
	"dsh-mobile-ustc/services/remote/internal/coldarchive"
	"dsh-mobile-ustc/services/remote/internal/testsupport"
)

func applyAuditColdExportFixtureMigration(t *testing.T, ctx context.Context, db *Postgres, direction string) {
	t.Helper()
	if direction != "up" && direction != "down" {
		t.Fatal("invalid fixture migration direction")
	}
	raw, err := os.ReadFile("../../../../deploy/sql/029_audit_cold_exports." + direction + ".sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, string(raw)); err != nil {
		t.Fatal("audit cold export fixture migration failed", err)
	}
}

func auditColdFixture(t *testing.T) (context.Context, *Postgres, AuditColdExportRequest, int64) {
	t.Helper()
	ctx, db := newPostgresIntegrationDatabase(t)
	enableAuditFixtureTime(t, ctx, db.DB)
	id := auditFixtureEntry(t, ctx, db.DB, "2000-01-01T00:00:00Z", "PRIVATE_AUDIT_COLD_BODY")
	batchRequest := auditArchiveFixtureRequest(t)
	batch, err := db.ArchiveAuditHistory(ctx, batchRequest)
	if err != nil || batch.Entries != 1 {
		t.Fatal("audit history fixture failed", err)
	}
	request := AuditColdExportRequest{ExportID: approvalTestUUID(t), DomainID: approvalTestUUID(t), DatabaseEpoch: OriginalDatabaseEpoch, BatchID: batch.BatchID,
		DestinationFingerprint: strings.Repeat("a", 64), Key: exportFixtureKey(t, 51)}
	return ctx, db, request, id
}

func expireAuditBatchFixture(t *testing.T, ctx context.Context, db *Postgres, batchID string) {
	t.Helper()
	tx, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `alter table audit_archive_batches disable trigger audit_archive_batch_guard`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `with moment as materialized(select clock_timestamp()-interval '2 years' as at)
	 update audit_archive_batches set archived_at=moment.at,cutoff=moment.at-interval '2160 hours',
	 retain_until=((moment.at at time zone 'UTC')+interval '1 year') at time zone 'UTC' from moment where id=$1`, batchID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `alter table audit_archive_batches enable trigger audit_archive_batch_guard`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestAuditColdExportPreparesRebuildsAndPublishesOneIdentity(t *testing.T) {
	ctx, db, request, id := auditColdFixture(t)
	state, artifact, err := db.PrepareAuditColdExport(ctx, request)
	if err != nil || state.State != "prepared" || state.EntryCount != 1 || len(artifact) == 0 {
		t.Fatal("audit cold export preparation failed", err)
	}
	payload, err := auditarchive.Open(request.Key, artifact, request.DomainID, request.ExportID)
	if err != nil || len(payload.Entries) != 1 || payload.Entries[0].SourceID != id || !bytes.Contains(payload.Entries[0].Source, []byte("PRIVATE_AUDIT_COLD_BODY")) || bytes.Contains(artifact, []byte("PRIVATE_AUDIT_COLD_BODY")) {
		t.Fatal("encrypted export lost or exposed source audit", err)
	}
	auditarchive.Clear(&payload)
	retry, none, err := db.PrepareAuditColdExport(ctx, request)
	if err != nil || len(none) != 0 || retry.ArtifactSHA256 != state.ArtifactSHA256 || !retry.PreparedAt.Equal(state.PreparedAt) {
		t.Fatal("audit cold preparation was not idempotent", err)
	}
	rebuilt, again, err := db.RebuildAuditColdExport(ctx, request)
	if err != nil || !bytes.Equal(artifact, again) || rebuilt.PayloadSHA256 != state.PayloadSHA256 {
		t.Fatal("prepared audit artifact was not reproducible", err)
	}
	changed := request
	changed.Key = exportFixtureKey(t, 52)
	if _, _, err := db.PrepareAuditColdExport(ctx, changed); !errors.Is(err, ErrAuditColdExportConflict) {
		t.Fatal("audit export key was rebound", err)
	}
	changed = request
	changed.DestinationFingerprint = strings.Repeat("b", 64)
	if _, _, err := db.PrepareAuditColdExport(ctx, changed); !errors.Is(err, ErrAuditColdExportConflict) {
		t.Fatal("audit export directory was rebound", err)
	}
	if _, err := db.FinishAuditColdExport(ctx, request, strings.Repeat("b", 64), len(artifact)); !errors.Is(err, ErrAuditColdExportConflict) {
		t.Fatal("wrong audit ciphertext was published", err)
	}
	state, err = db.FinishAuditColdExport(ctx, request, coldarchive.Digest(artifact), len(artifact))
	if err != nil || state.State != "published" {
		t.Fatal("audit cold publication failed", err)
	}
	if _, err := db.AbortAuditColdExport(ctx, request); !errors.Is(err, ErrAuditColdExportConflict) {
		t.Fatal("published audit export was aborted", err)
	}
	var prepared, published int
	if err := db.DB.QueryRowContext(ctx, `select count(*) filter(where action='audit.cold.export.prepared'),count(*) filter(where action='audit.cold.export.published') from audit_log`).Scan(&prepared, &published); err != nil || prepared != 1 || published != 1 {
		t.Fatal("audit export durable records were duplicated", prepared, published, err)
	}
	down, err := os.ReadFile("../../../../deploy/sql/029_audit_cold_exports.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := db.DB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, string(down)); err == nil {
		t.Fatal("rollback erased an audit export identity")
	}
	if _, err := conn.ExecContext(ctx, `rollback`); err != nil {
		t.Fatal(err)
	}
}

func TestAuditColdExportRemainsVerifiableAfterExpiredSourceDeletion(t *testing.T) {
	ctx, db, request, id := auditColdFixture(t)
	expireAuditBatchFixture(t, ctx, db, request.BatchID)
	_, artifact, err := db.PrepareAuditColdExport(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.FinishAuditColdExport(ctx, request, coldarchive.Digest(artifact), len(artifact)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `delete from audit_log_archive where source_id=$1`, id); err != nil {
		t.Fatal("published export did not release expired source", err)
	}
	state, err := db.AuditColdExportForVerification(ctx, request)
	if err != nil || state.State != "published" {
		t.Fatal("published export state became unavailable", err)
	}
	payload, err := auditarchive.Open(request.Key, artifact, request.DomainID, request.ExportID)
	if err != nil || len(payload.Entries) != 1 || payload.Entries[0].SourceID != id {
		t.Fatal("independent artifact lost its source after deletion", err)
	}
	auditarchive.Clear(&payload)
	if err := db.RecordAuditColdExportAccess(ctx, request, coldarchive.Digest(artifact), len(artifact), false); err != nil {
		t.Fatal("verification after source deletion was not audited", err)
	}
	if _, rebuilt, err := db.RebuildAuditColdExport(ctx, request); !errors.Is(err, ErrAuditColdIncomplete) || len(rebuilt) != 0 {
		t.Fatal("deleted source unexpectedly rebuilt an artifact", err)
	}
}

func TestAuditColdExportPinsExpiredSourceUntilAuditedAbort(t *testing.T) {
	ctx, db, request, id := auditColdFixture(t)
	expireAuditBatchFixture(t, ctx, db, request.BatchID)
	if _, _, err := db.PrepareAuditColdExport(ctx, request); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `delete from audit_log_archive where source_id=$1`, id); err == nil {
		t.Fatal("pending export did not pin audit history")
	}
	wrong := request
	wrong.Key = exportFixtureKey(t, 53)
	if _, err := db.AbortAuditColdExport(ctx, wrong); !errors.Is(err, ErrAuditColdExportConflict) {
		t.Fatal("wrong key aborted pending protection", err)
	}
	state, err := db.AbortAuditColdExport(ctx, request)
	if err != nil || state.State != "aborted" {
		t.Fatal("audit export abort failed", err)
	}
	if _, err := db.AbortAuditColdExport(ctx, request); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.RebuildAuditColdExport(ctx, request); !errors.Is(err, ErrAuditColdExportConflict) {
		t.Fatal("aborted audit export was rebuilt", err)
	}
	if _, err := db.DB.ExecContext(ctx, `delete from audit_log_archive where source_id=$1`, id); err != nil {
		t.Fatal("audited abort did not release expired source", err)
	}
	var audits int
	if err := db.DB.QueryRowContext(ctx, `select count(*) from audit_log where action='audit.cold.export.aborted'`).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("audit export abort was not durable", audits, err)
	}
}

func TestAuditColdExportPinsAgainstConcurrentExpiredDeletion(t *testing.T) {
	ctx, db, request, id := auditColdFixture(t)
	db.DB.SetMaxOpenConns(5)
	expireAuditBatchFixture(t, ctx, db, request.BatchID)
	if _, err := db.DB.ExecContext(ctx, `create function test_wait_audit_cold_export() returns trigger language plpgsql as $$
	 begin perform pg_advisory_xact_lock(763206); return new; end $$;
	 create trigger test_wait_audit_cold_export before insert on audit_cold_exports for each row execute function test_wait_audit_cold_export()`); err != nil {
		t.Fatal(err)
	}
	holder, err := db.DB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if _, err := holder.ExecContext(ctx, `select pg_advisory_lock(763206)`); err != nil {
		t.Fatal(err)
	}
	defer holder.ExecContext(context.Background(), `select pg_advisory_unlock(763206)`)
	prepared := make(chan error, 1)
	go func() {
		_, artifact, err := db.PrepareAuditColdExport(ctx, request)
		clear(artifact)
		prepared <- err
	}()
	waitForLock := func(pattern string) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for {
			var waiting bool
			if err := db.DB.QueryRowContext(ctx, `select exists(select 1 from pg_stat_activity where datname=current_database() and wait_event_type='Lock' and query like $1)`, pattern).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if waiting {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("fixture did not reach the expected audit export lock")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	waitForLock("insert into audit_cold_exports%")
	deleted := make(chan error, 1)
	go func() {
		_, err := db.DB.ExecContext(ctx, `delete from audit_log_archive where source_id=$1 /* audit-cold-expiry */`, id)
		deleted <- err
	}()
	waitForLock("delete from audit_log_archive%audit-cold-expiry%")
	if _, err := holder.ExecContext(ctx, `select pg_advisory_unlock(763206)`); err != nil {
		t.Fatal(err)
	}
	if err := <-prepared; err != nil {
		t.Fatal("audit cold preparation did not commit", err)
	}
	if err := <-deleted; err == nil {
		t.Fatal("concurrent expiry removed newly pinned audit history")
	}
	if _, err := db.AbortAuditColdExport(ctx, request); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `delete from audit_log_archive where source_id=$1`, id); err != nil {
		t.Fatal("audited abort did not release expired audit history", err)
	}
}

func TestAuditColdExportRejectsChangedOrIncompleteSource(t *testing.T) {
	ctx, db, request, id := auditColdFixture(t)
	if _, _, err := db.PrepareAuditColdExport(ctx, request); err != nil {
		t.Fatal(err)
	}
	tx, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `alter table audit_log_archive disable trigger audit_archive_entry_guard`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `update audit_log_archive set source=jsonb_set(source,'{metadata,marker}','"changed"'::jsonb) where source_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `alter table audit_log_archive enable trigger audit_archive_entry_guard`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, artifact, err := db.RebuildAuditColdExport(ctx, request); !errors.Is(err, ErrAuditColdExportConflict) || len(artifact) != 0 {
		t.Fatal("changed audit source reused its encryption material", err)
	}
	var denied int
	if err := db.DB.QueryRowContext(ctx, `select count(*) from audit_log where action='audit.cold.export.prepare' and result='conflict'`).Scan(&denied); err != nil || denied != 1 {
		t.Fatal("source conflict was not audited", denied, err)
	}
}

func TestAuditColdExportRejectsMissingHistoryAndAuditsFailure(t *testing.T) {
	ctx, db, request, id := auditColdFixture(t)
	expireAuditBatchFixture(t, ctx, db, request.BatchID)
	if _, err := db.DB.ExecContext(ctx, `delete from audit_log_archive where source_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if _, artifact, err := db.PrepareAuditColdExport(ctx, request); !errors.Is(err, ErrAuditColdIncomplete) || len(artifact) != 0 {
		t.Fatal("incomplete audit history was exported", err)
	}
	var denied, exports int
	if err := db.DB.QueryRowContext(ctx, `select (select count(*) from audit_log where action='audit.cold.export.prepare' and result='unavailable'),
	 (select count(*) from audit_cold_exports)`).Scan(&denied, &exports); err != nil || denied != 1 || exports != 0 {
		t.Fatal("incomplete source access was not audited", denied, exports, err)
	}
}

func TestAuditColdExportRejectsInvalidSourceAndAuditsFailure(t *testing.T) {
	ctx, db, request, id := auditColdFixture(t)
	tx, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `alter table audit_log_archive disable trigger audit_archive_entry_guard`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `update audit_log_archive set source=jsonb_set(source,'{id}',to_jsonb(source_id+1)) where source_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `alter table audit_log_archive enable trigger audit_archive_entry_guard`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, artifact, err := db.PrepareAuditColdExport(ctx, request); !errors.Is(err, ErrAuditColdSourceInvalid) || len(artifact) != 0 {
		t.Fatal("invalid audit source was exported", err)
	}
	var denied, exports int
	if err := db.DB.QueryRowContext(ctx, `select (select count(*) from audit_log where action='audit.cold.export.prepare' and result='failure'),
	 (select count(*) from audit_cold_exports)`).Scan(&denied, &exports); err != nil || denied != 1 || exports != 0 {
		t.Fatal("invalid audit source access was not recorded", denied, exports, err)
	}
}

func TestAuditColdExportDeferredAuditFailureLeavesNoPinOrArtifact(t *testing.T) {
	ctx, db, request, _ := auditColdFixture(t)
	if _, err := db.DB.ExecContext(ctx, `create function test_fail_audit_cold_commit() returns trigger language plpgsql as $$
	 begin if new.action='audit.cold.export.prepared' then raise exception 'fixture failure'; end if; return null; end $$;
	 create constraint trigger test_fail_audit_cold_commit after insert on audit_log deferrable initially deferred
	 for each row execute function test_fail_audit_cold_commit()`); err != nil {
		t.Fatal(err)
	}
	if _, artifact, err := db.PrepareAuditColdExport(ctx, request); !errors.Is(err, ErrDatabaseUnavailable) || len(artifact) != 0 {
		t.Fatal("failed audit commit produced an artifact", err)
	}
	var exports, audits int
	if err := db.DB.QueryRowContext(ctx, `select (select count(*) from audit_cold_exports),
	 (select count(*) from audit_log where action='audit.cold.export.prepared')`).Scan(&exports, &audits); err != nil || exports != 0 || audits != 0 {
		t.Fatal("failed audit commit left an export or audit", exports, audits, err)
	}
	if _, err := db.DB.ExecContext(ctx, `drop trigger test_fail_audit_cold_commit on audit_log; drop function test_fail_audit_cold_commit()`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.PrepareAuditColdExport(ctx, request); err != nil {
		t.Fatal("failed audit export could not be retried", err)
	}
}

func TestAuditColdExportConcurrentPreparationSharesOneArtifact(t *testing.T) {
	ctx, db, request, _ := auditColdFixture(t)
	type outcome struct {
		state    AuditColdExportState
		artifact []byte
		err      error
	}
	results := make(chan outcome, 4)
	var group sync.WaitGroup
	for range 4 {
		group.Go(func() {
			state, artifact, err := db.PrepareAuditColdExport(ctx, request)
			results <- outcome{state, artifact, err}
		})
	}
	group.Wait()
	close(results)
	created := 0
	var first AuditColdExportState
	for item := range results {
		if item.err != nil {
			t.Fatal(item.err)
		}
		if len(item.artifact) > 0 {
			created++
		}
		if first.ExportID == "" {
			first = item.state
		} else if first.ArtifactSHA256 != item.state.ArtifactSHA256 || first.Salt != item.state.Salt || first.Nonce != item.state.Nonce {
			t.Fatal("concurrent audit preparations changed artifact identity")
		}
	}
	if created != 1 {
		t.Fatal("concurrent preparations minted multiple audit artifacts", created)
	}
}

func TestAuditColdExportPendingStateSurvivesActualRecovery(t *testing.T) {
	ctx, db, request, id := auditColdFixture(t)
	expireAuditBatchFixture(t, ctx, db, request.BatchID)
	if _, _, err := db.PrepareAuditColdExport(ctx, request); err != nil {
		t.Fatal(err)
	}
	restoredCtx, database, _ := testsupport.RestoredPostgresDatabase(t, db.DB)
	restored := &Postgres{DB: database}
	epoch, operation := approvalTestUUID(t), approvalTestUUID(t)
	if _, err := restored.QuarantineRecovery(restoredCtx, operation, OriginalDatabaseEpoch, epoch); err != nil {
		t.Fatal(err)
	}
	manifest := RecoveryAuthority{Version: 1, Complete: true, RecoveryID: operation, DatabaseEpoch: epoch, Issuer: "https://id.example.edu", CapturedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Minute).UTC(), Users: []RecoveryUser{}}
	if _, err := restored.ReleaseRecovery(restoredCtx, epoch, manifest.Issuer, manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(restoredCtx, `delete from audit_log_archive where source_id=$1`, id); err == nil {
		t.Fatal("recovery lost pending audit source protection")
	}
	request.DatabaseEpoch = epoch
	if _, _, err := restored.RebuildAuditColdExport(restoredCtx, request); !errors.Is(err, ErrAuditColdExportConflict) {
		t.Fatal("old audit export rebound to restored epoch", err)
	}
	state, err := restored.AbortAuditColdExport(restoredCtx, request)
	if err != nil || state.State != "aborted" {
		t.Fatal("released recovery could not abort old export", err)
	}
	if _, err := database.ExecContext(restoredCtx, `delete from audit_log_archive where source_id=$1`, id); err != nil {
		t.Fatal("audited abort did not release audit source", err)
	}
}

func TestAuditColdExportAfterActualRestorePreservesUnknownAndKnownOrigins(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	enableAuditFixtureTime(t, ctx, db.DB)
	legacy := auditFixtureEntry(t, ctx, db.DB, "2000-01-01T00:00:00Z", "legacy")
	known := auditFixtureEntry(t, ctx, db.DB, "2000-01-02T00:00:00Z", "known")
	// Fixture-only simulation of a pre-provenance audit row.
	tx, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `alter table audit_log disable trigger audit_log_immutable`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `update audit_log set database_epoch=null,producer_xid=null where id=$1`, legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `alter table audit_log enable trigger audit_log_immutable`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	batch, err := db.ArchiveAuditHistory(ctx, auditArchiveFixtureRequest(t))
	if err != nil || batch.Entries != 2 {
		t.Fatal("mixed-origin audit history was not archived", err)
	}
	request := AuditColdExportRequest{ExportID: approvalTestUUID(t), DomainID: approvalTestUUID(t), DatabaseEpoch: OriginalDatabaseEpoch,
		BatchID: batch.BatchID, DestinationFingerprint: strings.Repeat("a", 64), Key: exportFixtureKey(t, 54)}
	_, artifact, err := db.PrepareAuditColdExport(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.FinishAuditColdExport(ctx, request, coldarchive.Digest(artifact), len(artifact)); err != nil {
		t.Fatal(err)
	}
	restoredCtx, database, _ := testsupport.RestoredPostgresDatabase(t, db.DB)
	restored := &Postgres{DB: database}
	epoch, operation := approvalTestUUID(t), approvalTestUUID(t)
	if _, err := restored.QuarantineRecovery(restoredCtx, operation, OriginalDatabaseEpoch, epoch); err != nil {
		t.Fatal(err)
	}
	manifest := RecoveryAuthority{Version: 1, Complete: true, RecoveryID: operation, DatabaseEpoch: epoch, Issuer: "https://id.example.edu", CapturedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Minute).UTC(), Users: []RecoveryUser{}}
	if _, err := restored.ReleaseRecovery(restoredCtx, epoch, manifest.Issuer, manifest); err != nil {
		t.Fatal(err)
	}
	request.DatabaseEpoch, request.DestinationFingerprint = epoch, strings.Repeat("b", 64)
	state, err := restored.AuditColdExportForVerification(restoredCtx, request)
	if err != nil || state.State != "published" || state.OperationEpoch != OriginalDatabaseEpoch {
		t.Fatal("old audit artifact was not verifiable in released recovery", err)
	}
	if err := restored.RecordAuditColdExportAccess(restoredCtx, request, coldarchive.Digest(artifact), len(artifact), false); err != nil {
		t.Fatal("recovered audit verification was not recorded", err)
	}
	if _, _, err := restored.PrepareAuditColdExport(restoredCtx, request); !errors.Is(err, ErrAuditColdExportConflict) {
		t.Fatal("old audit export was rebound to a new epoch", err)
	}
	request.ExportID = approvalTestUUID(t)
	_, fresh, err := restored.PrepareAuditColdExport(restoredCtx, request)
	if err != nil {
		t.Fatal("mixed-origin audit history could not be exported after recovery", err)
	}
	payload, err := auditarchive.Open(request.Key, fresh, request.DomainID, request.ExportID)
	if err != nil || payload.OperationEpoch != epoch || len(payload.Recoveries) != 1 || payload.Recoveries[0].ID != operation || len(payload.Entries) != 2 {
		t.Fatal("recovered audit export lost its lineage", err)
	}
	defer auditarchive.Clear(&payload)
	seen := map[int64]*string{}
	for _, entry := range payload.Entries {
		seen[entry.SourceID] = entry.SourceEpoch
	}
	if value, ok := seen[legacy]; !ok || value != nil {
		t.Fatal("unknown legacy origin was invented")
	}
	if value, ok := seen[known]; !ok || value == nil || *value != OriginalDatabaseEpoch {
		t.Fatal("known source origin was lost")
	}
}

func TestAuditColdExportIncludesOldEventLineageWhenBatchIsCreatedAfterRestore(t *testing.T) {
	ctx, source := newPostgresIntegrationDatabase(t)
	enableAuditFixtureTime(t, ctx, source.DB)
	id := auditFixtureEntry(t, ctx, source.DB, "2000-01-01T00:00:00Z", "old-source")
	restoredCtx, database, _ := testsupport.RestoredPostgresDatabase(t, source.DB)
	restored := &Postgres{DB: database}
	epoch, operation := approvalTestUUID(t), approvalTestUUID(t)
	if _, err := restored.QuarantineRecovery(restoredCtx, operation, OriginalDatabaseEpoch, epoch); err != nil {
		t.Fatal(err)
	}
	manifest := RecoveryAuthority{Version: 1, Complete: true, RecoveryID: operation, DatabaseEpoch: epoch, Issuer: "https://id.example.edu", CapturedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Minute).UTC(), Users: []RecoveryUser{}}
	if _, err := restored.ReleaseRecovery(restoredCtx, epoch, manifest.Issuer, manifest); err != nil {
		t.Fatal(err)
	}
	batchRequest := auditArchiveFixtureRequest(t)
	batchRequest.DatabaseEpoch = epoch
	batch, err := restored.ArchiveAuditHistory(restoredCtx, batchRequest)
	if err != nil || batch.Entries != 1 {
		t.Fatal("old event was not archived after recovery", err)
	}
	request := AuditColdExportRequest{ExportID: approvalTestUUID(t), DomainID: approvalTestUUID(t), DatabaseEpoch: epoch, BatchID: batch.BatchID,
		DestinationFingerprint: strings.Repeat("c", 64), Key: exportFixtureKey(t, 55)}
	_, artifact, err := restored.PrepareAuditColdExport(restoredCtx, request)
	if err != nil {
		t.Fatal("old event could not be exported with its lineage", err)
	}
	payload, err := auditarchive.Open(request.Key, artifact, request.DomainID, request.ExportID)
	if err != nil || payload.Batch.DatabaseEpoch != epoch || len(payload.Entries) != 1 || payload.Entries[0].SourceID != id || payload.Entries[0].SourceEpoch == nil ||
		*payload.Entries[0].SourceEpoch != OriginalDatabaseEpoch || len(payload.Recoveries) != 1 || payload.Recoveries[0].ID != operation {
		t.Fatal("new batch lost old-event provenance", err)
	}
	auditarchive.Clear(&payload)
}

func TestAuditColdExportLimitedRoleCannotAlterSourceOrRecoveryEpoch(t *testing.T) {
	ctx, db, request, _ := auditColdFixture(t)
	role := "dsh_audit_cold_" + strings.ReplaceAll(approvalTestUUID(t), "-", "")
	if _, err := db.DB.ExecContext(ctx, "create role "+role+" nologin"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := db.DB.ExecContext(cleanup, "reset role"); err != nil {
			t.Error(err)
			return
		}
		if _, err := db.DB.ExecContext(cleanup, "drop owned by "+role); err != nil {
			t.Error(err)
			return
		}
		if _, err := db.DB.ExecContext(cleanup, "drop role "+role); err != nil {
			t.Error(err)
		}
	})
	for _, statement := range []string{
		"grant usage on schema public to " + role,
		"grant select on audit_archive_batches,audit_log_archive,remote_recovery_state,remote_recovery_runs to " + role,
		"grant update(source_id) on audit_log_archive to " + role,
		"grant update(slot) on remote_recovery_state to " + role,
		"grant select,insert on audit_cold_exports to " + role,
		"grant update(state,completed_at) on audit_cold_exports to " + role,
		"grant insert(actor_type,actor_id,action,result,metadata) on audit_log to " + role,
		"grant usage,select on sequence audit_log_id_seq to " + role,
	} {
		if _, err := db.DB.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	db.DB.SetMaxOpenConns(1)
	if _, err := db.DB.ExecContext(ctx, "set role "+role); err != nil {
		t.Fatal(err)
	}
	_, artifact, err := db.PrepareAuditColdExport(ctx, request)
	if err != nil {
		t.Fatal("limited role could not prepare audit export", err)
	}
	if _, err := db.FinishAuditColdExport(ctx, request, coldarchive.Digest(artifact), len(artifact)); err != nil {
		t.Fatal("limited role could not publish audit export", err)
	}
	if _, err := db.DB.ExecContext(ctx, `update audit_log_archive set source_id=source_id`); err == nil {
		t.Fatal("row-lock privilege allowed source mutation")
	}
	if _, err := db.DB.ExecContext(ctx, `update audit_cold_exports set salt=decode(repeat('00',32),'hex')`); err == nil {
		t.Fatal("publisher changed encryption identity")
	}
	if _, err := db.DB.ExecContext(ctx, `update remote_recovery_state set epoch='ffffffff-ffff-4fff-8fff-ffffffffffff'`); err == nil {
		t.Fatal("publisher changed recovery epoch")
	}
}
