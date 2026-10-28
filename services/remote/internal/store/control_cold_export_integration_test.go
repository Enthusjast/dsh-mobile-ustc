package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/coldarchive"
	"dsh-mobile-ustc/services/remote/internal/testsupport"
)

func exportFixtureKey(t *testing.T, value byte) *coldarchive.Key {
	t.Helper()
	key, err := coldarchive.NewKey("fixture-key", bytes.Repeat([]byte{value}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Close)
	return key
}
func exportFixtureRequest(t *testing.T, batch string, key *coldarchive.Key) ControlExportRequest {
	t.Helper()
	return ControlExportRequest{ExportID: approvalTestUUID(t), DomainID: approvalTestUUID(t), DatabaseEpoch: OriginalDatabaseEpoch, BatchID: batch, DestinationFingerprint: strings.Repeat("a", 64), Key: key}
}
func populatedArchive(t *testing.T, ctx context.Context, db *Postgres) ControlArchiveResult {
	t.Helper()
	consumer, err := db.NewControlConsumer(ctx, controlNodeA)
	if err != nil {
		t.Fatal(err)
	}
	id := archiveFixtureEvent(t, ctx, db.DB, "device.revoked", "2000-01-01T00:00:00Z", "2000-01-02T00:00:00Z")
	if err := consumer.MarkControlEventPublished(ctx, id); err != nil {
		t.Fatal(err)
	}
	batch, err := db.ArchiveControlEvents(ctx, archiveFixtureRequest(t))
	if err != nil || batch.Events != 1 {
		t.Fatal("archive fixture", err)
	}
	return batch
}

func expiredArchive(t *testing.T, ctx context.Context, db *Postgres) ControlArchiveResult {
	t.Helper()
	id := archiveFixtureEvent(t, ctx, db.DB, "device.revoked", "2000-01-01T00:00:00Z", "2000-01-02T00:00:00Z")
	var at, cutoff, retained time.Time
	if err := db.DB.QueryRowContext(ctx, `with moment as materialized(select clock_timestamp()-interval '2 years' as at)
	 select at,at-interval '2160 hours',((at at time zone 'UTC')+interval '1 year') at time zone 'UTC' from moment`).Scan(&at, &cutoff, &retained); err != nil {
		t.Fatal(err)
	}
	result := ControlArchiveResult{BatchID: approvalTestUUID(t), DatabaseEpoch: OriginalDatabaseEpoch, Limit: 1, RetentionYears: 1, Cutoff: cutoff, ArchivedAt: at, RetainUntil: retained, Events: 1}
	tx, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `insert into control_archive_batches(id,database_epoch,batch_limit,retention_years,cutoff,archived_at,retain_until,event_count,previous_epoch_count)
	 values($1,$2,1,1,$3,$4,$5,1,0)`, result.BatchID, result.DatabaseEpoch, cutoff, at, retained); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `insert into control_outbox_archive(event_id,batch_id,batch_epoch,database_epoch,topic,source_created_at,source,reason,archived_at,retain_until)
	 select e.id,$2,$3,e.database_epoch,e.topic,e.created_at,to_jsonb(e),'covered',$4,$5 from control_outbox e where e.id=$1`, id, result.BatchID, result.DatabaseEpoch, at, retained); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `delete from control_outbox where id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestControlColdExportIdempotentPreparationRebuildAndPublication(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	batch := populatedArchive(t, ctx, db)
	key := exportFixtureKey(t, 7)
	request := exportFixtureRequest(t, batch.BatchID, key)
	result, artifact, err := db.PrepareControlExport(ctx, request)
	if err != nil || result.State != "prepared" || result.Events != 1 || result.Acknowledgements != 1 || len(artifact) == 0 {
		t.Fatal("preparation", result, err)
	}
	opened, err := coldarchive.Open(key, artifact, request.DomainID, request.ExportID)
	if err != nil || opened.Batch.ID != batch.BatchID || len(opened.Events) != 1 || len(opened.Events[0].Acknowledgements) != 1 {
		t.Fatal("artifact lost source or ack", err)
	}
	retry, none, err := db.PrepareControlExport(ctx, request)
	if err != nil || len(none) != 0 || !retry.PreparedAt.Equal(result.PreparedAt) || retry.ArtifactSHA256 != result.ArtifactSHA256 {
		t.Fatal("retry changed prepared operation", err)
	}
	rebuilt, again, err := db.RebuildControlExport(ctx, request)
	if err != nil || !bytes.Equal(artifact, again) || rebuilt.PayloadSHA256 != result.PayloadSHA256 {
		t.Fatal("retry could not reconstruct exact ciphertext", err)
	}
	changed := request
	changed.DestinationFingerprint = strings.Repeat("b", 64)
	if _, err := db.ControlExport(ctx, changed); !errors.Is(err, ErrControlExportConflict) {
		t.Fatal("destination was rebound", err)
	}
	changed = request
	changed.Key = exportFixtureKey(t, 8)
	if _, err := db.ControlExport(ctx, changed); !errors.Is(err, ErrControlExportConflict) {
		t.Fatal("key was rebound", err)
	}
	if _, err := db.FinishControlExport(ctx, request, strings.Repeat("b", 64), len(artifact)); !errors.Is(err, ErrControlExportConflict) {
		t.Fatal("wrong file digest was published", err)
	}
	published, err := db.FinishControlExport(ctx, request, coldarchive.Digest(artifact), len(artifact))
	if err != nil || published.State != "published" || published.CompletedAt == nil {
		t.Fatal("publication", err)
	}
	retry, err = db.FinishControlExport(ctx, request, coldarchive.Digest(artifact), len(artifact))
	if err != nil || !retry.CompletedAt.Equal(*published.CompletedAt) {
		t.Fatal("publication retry was not stable", err)
	}
	if _, err := db.AbortControlExport(ctx, request); !errors.Is(err, ErrControlExportConflict) {
		t.Fatal("published export was aborted", err)
	}
	var preparedAudits, publishedAudits int
	if err := db.DB.QueryRowContext(ctx, `select count(*) filter(where action='control.archive.export.prepared'),count(*) filter(where action='control.archive.export.published') from audit_log`).Scan(&preparedAudits, &publishedAudits); err != nil || preparedAudits != 1 || publishedAudits != 1 {
		t.Fatal("export audits were duplicated", preparedAudits, publishedAudits, err)
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{result.KeyFingerprint, result.DestinationFingerprint, result.PayloadSHA256, string(result.Salt[:]), "device.revoked"} {
		if strings.Contains(string(raw), private) {
			t.Fatal("export summary exposed protected material")
		}
	}
}

func TestControlColdExportPinsExpiredSourceUntilAuditedAbort(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	batch := expiredArchive(t, ctx, db)
	key := exportFixtureKey(t, 6)
	request := exportFixtureRequest(t, batch.BatchID, key)
	if _, _, err := db.PrepareControlExport(ctx, request); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `delete from control_outbox_archive where batch_id=$1`, batch.BatchID); err == nil {
		t.Fatal("unfinished export did not pin source")
	}
	wrong := request
	wrong.Key = exportFixtureKey(t, 9)
	if _, err := db.AbortControlExport(ctx, wrong); !errors.Is(err, ErrControlExportConflict) {
		t.Fatal("wrong key aborted source protection", err)
	}
	aborted, err := db.AbortControlExport(ctx, request)
	if err != nil || aborted.State != "aborted" {
		t.Fatal("abort", err)
	}
	if _, err := db.AbortControlExport(ctx, request); err != nil {
		t.Fatal("abort retry", err)
	}
	if _, _, err := db.RebuildControlExport(ctx, request); !errors.Is(err, ErrControlExportConflict) {
		t.Fatal("aborted export rebuilt", err)
	}
	if _, err := db.DB.ExecContext(ctx, `delete from control_outbox_archive where batch_id=$1`, batch.BatchID); err != nil {
		t.Fatal("explicit audited abort did not release expired source", err)
	}
	var count int
	if err := db.DB.QueryRowContext(ctx, `select count(*) from audit_log where action='control.archive.export.aborted'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("abort audit was lost or duplicated", count, err)
	}
}

func TestControlColdExportPinsSourceAgainstConcurrentExpiryDeletion(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	db.DB.SetMaxOpenConns(5)
	batch := expiredArchive(t, ctx, db)
	request := exportFixtureRequest(t, batch.BatchID, exportFixtureKey(t, 10))
	// Pause the real preparation at its INSERT, after the source row is locked.
	// This is a fixture-only trigger in the disposable database.
	if _, err := db.DB.ExecContext(ctx, `create function test_hold_export_insert() returns trigger language plpgsql as $$
	 begin perform pg_advisory_xact_lock(763201); return new; end $$;
	 create trigger test_hold_export_insert before insert on control_archive_exports for each row execute function test_hold_export_insert()`); err != nil {
		t.Fatal(err)
	}
	holder, err := db.DB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if _, err := holder.ExecContext(ctx, `select pg_advisory_lock(763201)`); err != nil {
		t.Fatal(err)
	}
	defer holder.ExecContext(context.Background(), `select pg_advisory_unlock(763201)`)
	prepared := make(chan error, 1)
	go func() {
		_, artifact, err := db.PrepareControlExport(ctx, request)
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
				t.Fatal("fixture did not reach the expected database lock")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	waitForLock("insert into control_archive_exports%")
	deleted := make(chan error, 1)
	go func() {
		_, err := db.DB.ExecContext(ctx, `delete from control_outbox_archive where batch_id=$1 /* expiry-race */`, batch.BatchID)
		deleted <- err
	}()
	waitForLock("delete from control_outbox_archive%expiry-race%")
	if _, err := holder.ExecContext(ctx, `select pg_advisory_unlock(763201)`); err != nil {
		t.Fatal(err)
	}
	if err := <-prepared; err != nil {
		t.Fatal("preparation did not commit", err)
	}
	if err := <-deleted; err == nil {
		t.Fatal("concurrent expiry deleted a newly pinned source")
	}
	if _, err := db.AbortControlExport(ctx, request); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `delete from control_outbox_archive where batch_id=$1`, batch.BatchID); err != nil {
		t.Fatal("audited abort did not release the source", err)
	}
}

func TestControlColdExportRejectsSourceChangesBeforeReusingMaterial(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	batch := populatedArchive(t, ctx, db)
	key := exportFixtureKey(t, 5)
	request := exportFixtureRequest(t, batch.BatchID, key)
	if _, _, err := db.PrepareControlExport(ctx, request); err != nil {
		t.Fatal(err)
	}
	// A privileged fixture simulates corruption; normal UPDATE is forbidden.
	tx, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `alter table control_outbox_archive disable trigger control_outbox_archive_immutable`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `update control_outbox_archive set source=jsonb_set(source,'{payload,marker}','"changed"'::jsonb) where batch_id=$1`, batch.BatchID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `alter table control_outbox_archive enable trigger control_outbox_archive_immutable`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, artifact, err := db.RebuildControlExport(ctx, request); !errors.Is(err, ErrControlExportConflict) || len(artifact) != 0 {
		t.Fatal("changed source reused its GCM material", err)
	}
}

func TestControlColdExportRejectsLateEventAndAcknowledgementInsertion(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	batch := populatedArchive(t, ctx, db)
	var id string
	if err := db.DB.QueryRowContext(ctx, `select event_id::text from control_outbox_archive where batch_id=$1`, batch.BatchID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `insert into control_event_ack_archive(node_id,event_id,applied_at,source)
	 select $1::uuid,$2::uuid,clock_timestamp(),jsonb_build_object('node_id',$1::uuid,'event_id',$2::uuid,'applied_at',clock_timestamp())`, controlNodeB, id); err == nil {
		t.Fatal("an old archive acquired a new acknowledgement")
	}
	if _, err := db.DB.ExecContext(ctx, `insert into control_outbox_archive(event_id,batch_id,batch_epoch,database_epoch,topic,source_created_at,source,reason,archived_at,retain_until)
	 select $2::uuid,batch_id,batch_epoch,database_epoch,topic,source_created_at,jsonb_set(source,'{id}',to_jsonb($2::uuid)),'covered',archived_at,retain_until
	 from control_outbox_archive where event_id=$1`, id, approvalTestUUID(t)); err == nil {
		t.Fatal("an old batch acquired a new event")
	}
}

func TestControlColdExportPendingStateSurvivesRealRecoveryAndCanBeExplicitlyAborted(t *testing.T) {
	ctx, source := newPostgresIntegrationDatabase(t)
	batch := expiredArchive(t, ctx, source)
	key := exportFixtureKey(t, 4)
	request := exportFixtureRequest(t, batch.BatchID, key)
	if _, _, err := source.PrepareControlExport(ctx, request); err != nil {
		t.Fatal(err)
	}
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
	if _, err := database.ExecContext(restoredCtx, `delete from control_outbox_archive where batch_id=$1`, batch.BatchID); err == nil {
		t.Fatal("recovery lost the pending-export pin")
	}
	request.DatabaseEpoch = epoch
	if _, err := restored.ControlExport(restoredCtx, request); !errors.Is(err, ErrControlExportConflict) {
		t.Fatal("old prepared export was rebound to a new epoch", err)
	}
	aborted, err := restored.AbortControlExport(restoredCtx, request)
	if err != nil || aborted.State != "aborted" {
		t.Fatal("recovered operator could not retire old pending intent", err)
	}
	if _, err := database.ExecContext(restoredCtx, `delete from control_outbox_archive where batch_id=$1`, batch.BatchID); err != nil {
		t.Fatal("audited old-epoch abort did not release source", err)
	}
}

func TestControlColdExportConcurrentPreparationsShareOneArtifactIdentity(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	batch := populatedArchive(t, ctx, db)
	request := exportFixtureRequest(t, batch.BatchID, exportFixtureKey(t, 3))
	type outcome struct {
		state    ControlExportState
		artifact []byte
		err      error
	}
	results := make(chan outcome, 4)
	var callers sync.WaitGroup
	for range 4 {
		callers.Go(func() {
			state, artifact, err := db.PrepareControlExport(ctx, request)
			results <- outcome{state, artifact, err}
		})
	}
	callers.Wait()
	close(results)
	created := 0
	var first ControlExportState
	for item := range results {
		if item.err != nil {
			t.Fatal(item.err)
		}
		if len(item.artifact) > 0 {
			created++
		}
		if first.ExportID == "" {
			first = item.state
		} else if item.state.ArtifactSHA256 != first.ArtifactSHA256 || item.state.Salt != first.Salt || item.state.Nonce != first.Nonce {
			t.Fatal("concurrent callers created different encryption identities")
		}
	}
	if created != 1 {
		t.Fatal("concurrent preparations minted multiple artifacts", created)
	}
	var count int
	if err := db.DB.QueryRowContext(ctx, `select count(*) from audit_log where action='control.archive.export.prepared'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("concurrent preparation duplicated audit", count, err)
	}
}
