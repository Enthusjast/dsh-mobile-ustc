package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/testsupport"
)

func archiveFixtureEvent(t *testing.T, ctx context.Context, db interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, topic, created, published string) string {
	t.Helper()
	var id string
	err := db.QueryRowContext(ctx, `insert into control_outbox(topic,payload,created_at,published_at)
	 values($1,jsonb_build_object('device_id',$2::text),$3::timestamptz,nullif($4,'')::timestamptz) returning id::text`, topic, controlDevice, created, published).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func archiveFixtureRequest(t *testing.T) ControlArchiveRequest {
	t.Helper()
	return ControlArchiveRequest{BatchID: approvalTestUUID(t), DatabaseEpoch: OriginalDatabaseEpoch, Limit: 64, RetentionYears: 1}
}

func TestControlArchiveNeedsEveryConsumerAndKeepsUnknownUnpublishedAndRecentEvents(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	old := "2000-01-01T00:00:00Z"
	for _, item := range [][3]string{{"device.revoked", old, ""}, {"device.revoked", old, time.Now().UTC().Format(time.RFC3339Nano)},
		{"file.clean", old, old}, {"future.control", old, old}} {
		archiveFixtureEvent(t, ctx, db.DB, item[0], item[1], item[2])
	}
	a, err := db.NewControlConsumer(ctx, controlNodeA)
	if err != nil {
		t.Fatal(err)
	}
	b, err := db.NewControlConsumer(ctx, controlNodeB)
	if err != nil {
		t.Fatal(err)
	}
	id := archiveFixtureEvent(t, ctx, db.DB, "device.revoked", old, old)
	if _, err := db.DB.ExecContext(ctx, `delete from control_outbox where id=$1`, id); err == nil {
		t.Fatal("unarchived source event could be deleted directly")
	}
	var original []byte
	if err := db.DB.QueryRowContext(ctx, `select to_jsonb(e) from control_outbox e where id=$1`, id).Scan(&original); err != nil {
		t.Fatal(err)
	}
	if err := a.MarkControlEventPublished(ctx, id); err != nil {
		t.Fatal(err)
	}
	request := archiveFixtureRequest(t)
	result, err := db.ArchiveControlEvents(ctx, request)
	if err != nil || result.Events != 0 {
		t.Fatal("one local publication retired another consumer's source", result, err)
	}
	if _, err := db.DB.ExecContext(ctx, `update control_consumers set lease_until=clock_timestamp()-interval '1 day' where node_id=$1`, b.node); err != nil {
		t.Fatal(err)
	}
	result, err = db.ArchiveControlEvents(ctx, archiveFixtureRequest(t))
	if err != nil || result.Events != 0 {
		t.Fatal("offline stable consumer lost its backlog", result, err)
	}
	b, err = db.NewControlConsumer(ctx, controlNodeB)
	if err != nil {
		t.Fatal(err)
	}
	if !consumerPendingIDs(t, ctx, b, 128)[id] {
		t.Fatal("stable restart lost retained event")
	}
	if err := b.MarkControlEventPublished(ctx, id); err != nil {
		t.Fatal(err)
	}
	var originalAcks []byte
	if err := db.DB.QueryRowContext(ctx, `select jsonb_agg(to_jsonb(a) order by a.node_id) from control_event_acks a where a.event_id=$1`, id).Scan(&originalAcks); err != nil {
		t.Fatal(err)
	}
	// Repeating an empty operation remains empty even after eligibility changes.
	result, err = db.ArchiveControlEvents(ctx, request)
	if err != nil || result.Events != 0 {
		t.Fatal("idempotent retry archived different work", result, err)
	}
	request = archiveFixtureRequest(t)
	request.RetentionYears = 3
	result, err = db.ArchiveControlEvents(ctx, request)
	if err != nil || result.Events != 1 || result.PreviousEpochEvents != 0 {
		t.Fatal("covered source did not archive", result, err)
	}
	var preserved bool
	var source, acks int
	if err := db.DB.QueryRowContext(ctx, `select source=$2::jsonb and retain_until>=archived_at+interval '3 years' and reason='covered' from control_outbox_archive where event_id=$1`, id, string(original)).Scan(&preserved); err != nil || !preserved {
		t.Fatal("full source row or retention was lost", err)
	}
	if err := db.DB.QueryRowContext(ctx, `select (select count(*) from control_outbox),(select count(*) from control_event_acks where event_id=$1)`, id).Scan(&source, &acks); err != nil || source != 4 || acks != 0 {
		t.Fatal("archive deleted unrelated rows or left hot acknowledgements", source, acks, err)
	}
	var preservedAcks bool
	if err := db.DB.QueryRowContext(ctx, `select count(*)=2 and jsonb_agg(a.source order by a.node_id)=$2::jsonb from control_event_ack_archive a where a.event_id=$1`, id, string(originalAcks)).Scan(&preservedAcks); err != nil || !preservedAcks {
		t.Fatal("per-node acknowledgement facts were not preserved", err)
	}
	for _, query := range []string{`update control_event_ack_archive set source='{}'::jsonb`, `delete from control_event_ack_archive`} {
		if _, err := db.DB.ExecContext(ctx, query); err == nil {
			t.Fatal("archived acknowledgement was independently modified")
		}
	}
	for _, consumer := range []*ControlConsumer{a, b} {
		if err := consumer.MarkControlEventPublished(ctx, id); err != nil {
			t.Fatal("late duplicate ack failed for an already retired fact", err)
		}
	}
	retry, err := db.ArchiveControlEvents(ctx, request)
	if err != nil || retry.Events != 1 || !retry.ArchivedAt.Equal(result.ArchivedAt) {
		t.Fatal("committed batch retry changed", retry, err)
	}
	request.Limit--
	if _, err := db.ArchiveControlEvents(ctx, request); !errors.Is(err, ErrControlArchiveConflict) {
		t.Fatal("changed operation parameters succeeded", err)
	}
	request.Limit++
	request.RetentionYears = 1
	if _, err := db.ArchiveControlEvents(ctx, request); !errors.Is(err, ErrControlArchiveConflict) {
		t.Fatal("changed retention on the same batch succeeded", err)
	}
}

func TestControlArchiveRollbackImmutabilityRetentionAndBoundedBatches(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	if _, err := db.DB.ExecContext(ctx, `insert into control_outbox(topic,payload,created_at,published_at)
	 select 'device.revoked',jsonb_build_object('device_id',$1::text),'2000-01-01','2000-01-02' from generate_series(1,130)`, controlDevice); err != nil {
		t.Fatal(err)
	}
	consumer, err := db.NewControlConsumer(ctx, controlNodeA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `insert into control_event_acks(node_id,event_id)
	 select $1,id from control_outbox order by created_at,id limit 1`, consumer.node); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `create function fixture_archive_commit_failure() returns trigger language plpgsql as $$ begin if new.action='control.archive' then raise exception 'PRIVATE_ARCHIVE_FAILURE';end if;return null;end $$;
	 create constraint trigger fixture_archive_commit_failure after insert on audit_log deferrable initially deferred for each row execute function fixture_archive_commit_failure()`); err != nil {
		t.Fatal(err)
	}
	request := archiveFixtureRequest(t)
	request.Limit = 128
	if _, err := db.ArchiveControlEvents(ctx, request); !errors.Is(err, ErrDatabaseUnavailable) {
		t.Fatal("failed audit commit appeared successful", err)
	}
	var hot, cold, batches, liveAcks, archivedAcks int
	if err := db.DB.QueryRowContext(ctx, `select (select count(*) from control_outbox),(select count(*) from control_outbox_archive),(select count(*) from control_archive_batches),
	 (select count(*) from control_event_acks),(select count(*) from control_event_ack_archive)`).Scan(&hot, &cold, &batches, &liveAcks, &archivedAcks); err != nil || hot != 130 || cold != 0 || batches != 0 || liveAcks != 1 || archivedAcks != 0 {
		t.Fatal("failed commit partially archived", hot, cold, batches, liveAcks, archivedAcks, err)
	}
	if _, err := db.DB.ExecContext(ctx, `drop trigger fixture_archive_commit_failure on audit_log`); err != nil {
		t.Fatal(err)
	}
	result, err := db.ArchiveControlEvents(ctx, request)
	if err != nil || result.Events != 128 {
		t.Fatal("batch exceeded or missed its bound", result, err)
	}
	if err := db.DB.QueryRowContext(ctx, `select count(*) from control_event_ack_archive`).Scan(&archivedAcks); err != nil || archivedAcks != 1 {
		t.Fatal("successful batch lost acknowledgement", archivedAcks, err)
	}
	for _, query := range []string{`update control_outbox_archive set source='{}'::jsonb`, `delete from control_outbox_archive`,
		`update control_archive_batches set event_count=0`, `delete from control_archive_batches`,
		`truncate table control_outbox cascade`, `truncate table control_event_acks`, `truncate table control_consumers cascade`,
		`truncate table control_outbox_archive cascade`, `truncate table control_event_ack_archive`, `truncate table control_archive_batches cascade`} {
		if _, err := db.DB.ExecContext(ctx, query); err == nil {
			t.Fatal("archive identity or unexpired retention was mutable")
		}
	}
	result, err = db.ArchiveControlEvents(ctx, archiveFixtureRequest(t))
	if err != nil || result.Events != 2 {
		t.Fatal("bounded continuation failed", result, err)
	}
	var total int
	if err := db.DB.QueryRowContext(ctx, `select count(*) from audit_log where action='control.archive'`).Scan(&total); err != nil || total != 2 {
		t.Fatal("rolled-back/duplicate batches wrote audit", total, err)
	}
	down, err := os.ReadFile("../../../../deploy/sql/022_control_archive.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	connection, err := db.DB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := connection.ExecContext(ctx, string(down)); err == nil {
		t.Fatal("archive history was destructively rolled back")
	}
	if _, err := connection.ExecContext(ctx, `rollback`); err != nil {
		t.Fatal(err)
	}
}

func TestControlArchiveHonorsInflightConsumerBootstrapAndLateProducer(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	block, err := db.DB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer block.Close()
	if _, err := block.ExecContext(ctx, `select pg_advisory_lock(1380012611,2)`); err != nil {
		t.Fatal(err)
	}
	defer block.ExecContext(ctx, `select pg_advisory_unlock_all()`)
	if _, err := db.DB.ExecContext(ctx, `create function fixture_hold_consumer() returns trigger language plpgsql as $$ begin perform pg_advisory_xact_lock(1380012611,2);return new;end $$;
	 create trigger fixture_hold_consumer before insert on control_consumers for each row execute function fixture_hold_consumer()`); err != nil {
		t.Fatal(err)
	}
	producer, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer producer.Rollback()
	id := archiveFixtureEvent(t, ctx, producer, "device.revoked", "2000-01-01T00:00:00Z", "2000-01-02T00:00:00Z")
	type outcome struct {
		consumer *ControlConsumer
		err      error
	}
	registered := make(chan outcome, 1)
	go func() {
		consumer, err := db.NewControlConsumer(ctx, controlNodeA)
		registered <- outcome{consumer, err}
	}()
	deadline := time.Now().Add(time.Second)
	for {
		var waiting bool
		if err := db.DB.QueryRowContext(ctx, `select exists(select 1 from pg_stat_activity where datname=current_database() and wait_event='advisory' and query like '%insert into control_consumers%')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("consumer did not reach its held bootstrap")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := producer.Commit(); err != nil {
		t.Fatal(err)
	}
	type archiveOutcome struct {
		result ControlArchiveResult
		err    error
	}
	archived := make(chan archiveOutcome, 1)
	request := archiveFixtureRequest(t)
	go func() {
		result, err := db.ArchiveControlEvents(ctx, request)
		archived <- archiveOutcome{result, err}
	}()
	select {
	case result := <-archived:
		t.Fatal("archive passed an uncommitted consumer coverage snapshot", result)
	case <-time.After(30 * time.Millisecond):
	}
	if _, err := block.ExecContext(ctx, `select pg_advisory_unlock_all()`); err != nil {
		t.Fatal(err)
	}
	registeredResult := <-registered
	if registeredResult.err != nil {
		t.Fatal(registeredResult.err)
	}
	archivedResult := <-archived
	if archivedResult.err != nil || archivedResult.result.Events != 0 {
		t.Fatal("late producer escaped bootstrap coverage", archivedResult)
	}
	if !consumerPendingIDs(t, ctx, registeredResult.consumer, 128)[id] {
		t.Fatal("archive swallowed a late producer")
	}
	if err := registeredResult.consumer.MarkControlEventPublished(ctx, id); err != nil {
		t.Fatal(err)
	}
	result, err := db.ArchiveControlEvents(ctx, archiveFixtureRequest(t))
	if err != nil || result.Events != 1 {
		t.Fatal("late producer did not become eligible after apply", result, err)
	}
}

func TestControlArchiveGateIsBoundedAndDoesNotBlockConsumerRenewal(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	id := archiveFixtureEvent(t, ctx, db.DB, "device.revoked", "2000-01-01T00:00:00Z", "2000-01-02T00:00:00Z")
	consumer, err := db.NewControlConsumer(ctx, controlNodeA)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Rollback()
	if err := lockControlArchive(ctx, gate, true); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []func(context.Context) error{
		func(ctx context.Context) error {
			_, err := db.ArchiveControlEvents(ctx, archiveFixtureRequest(t))
			return err
		},
		func(ctx context.Context) error { return consumer.MarkControlEventPublished(ctx, id) },
		func(ctx context.Context) error { return consumer.Release(ctx) },
		func(ctx context.Context) error { _, err := db.NewControlConsumer(ctx, controlNodeB); return err },
	} {
		bounded, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		err := operation(bounded)
		cancel()
		if !errors.Is(err, ErrDatabaseUnavailable) {
			t.Fatal("maintenance gate ignored bounded cancellation", err)
		}
	}
	if err := consumer.Renew(ctx); err != nil {
		t.Fatal("archive gate delayed consumer lease ownership", err)
	}
	if _, err := consumer.PendingControlEvents(ctx, 128); err != nil {
		t.Fatal("archive gate delayed the reader", err)
	}
	if err := gate.Rollback(); err != nil {
		t.Fatal(err)
	}
	result, err := db.ArchiveControlEvents(ctx, archiveFixtureRequest(t))
	if err != nil || result.Events != 1 {
		t.Fatal("cancelled archive left partial state or lock", result, err)
	}
}

func TestControlArchiveConcurrentRetriesCommitOneStableBatch(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	for range 5 {
		archiveFixtureEvent(t, ctx, db.DB, "device.revoked", "2000-01-01T00:00:00Z", "2000-01-02T00:00:00Z")
	}
	request := archiveFixtureRequest(t)
	request.Limit = 2
	type outcome struct {
		result ControlArchiveResult
		err    error
	}
	results := make(chan outcome, 4)
	var workers sync.WaitGroup
	for range 4 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			result, err := db.ArchiveControlEvents(ctx, request)
			results <- outcome{result, err}
		}()
	}
	workers.Wait()
	close(results)
	var first ControlArchiveResult
	for item := range results {
		if item.err != nil || item.result.Events != 2 {
			t.Fatal("concurrent retry did not reconcile", item.result, item.err)
		}
		if first.BatchID == "" {
			first = item.result
			continue
		}
		if item.result.BatchID != first.BatchID || !item.result.ArchivedAt.Equal(first.ArchivedAt) || !item.result.Cutoff.Equal(first.Cutoff) {
			t.Fatal("concurrent retry selected different work", item.result)
		}
	}
	var hot, cold, batches, audits int
	if err := db.DB.QueryRowContext(ctx, `select (select count(*) from control_outbox),(select count(*) from control_outbox_archive),
	 (select count(*) from control_archive_batches),(select count(*) from audit_log where action='control.archive')`).Scan(&hot, &cold, &batches, &audits); err != nil || hot != 3 || cold != 2 || batches != 1 || audits != 1 {
		t.Fatal("concurrent retry duplicated mutation or audit", hot, cold, batches, audits, err)
	}
}

func TestControlConsumerEphemeralReleaseRetainsCurrentEpochBehavior(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	consumer, err := db.NewControlConsumer(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	id := archiveFixtureEvent(t, ctx, db.DB, "device.revoked", "2000-01-01T00:00:00Z", "2000-01-02T00:00:00Z")
	if err := consumer.MarkControlEventPublished(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := consumer.Release(ctx); err != nil {
		t.Fatal(err)
	}
	var consumers, acks, events int
	if err := db.DB.QueryRowContext(ctx, `select (select count(*) from control_consumers where node_id=$1),
	 (select count(*) from control_event_acks where event_id=$2),(select count(*) from control_outbox where id=$2)`, consumer.node, id).Scan(&consumers, &acks, &events); err != nil || consumers != 0 || acks != 0 || events != 1 {
		t.Fatal("current-epoch ephemeral release changed its normal source semantics", consumers, acks, events, err)
	}
}

func TestControlArchiveMigrationRollbackOnlyBeforeUseOrRecovery(t *testing.T) {
	down, err := os.ReadFile("../../../../deploy/sql/022_control_archive.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, err := os.ReadFile("../../../../deploy/sql/022_control_archive.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	newerDown, err := os.ReadFile("../../../../deploy/sql/023_control_cold_exports.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	newerUp, err := os.ReadFile("../../../../deploy/sql/023_control_cold_exports.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	importDown, err := os.ReadFile("../../../../deploy/sql/024_control_cold_imports.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	importUp, err := os.ReadFile("../../../../deploy/sql/024_control_cold_imports.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	evidenceDown, err := os.ReadFile("../../../../deploy/sql/025_approval_decision_evidence.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	evidenceUp, err := os.ReadFile("../../../../deploy/sql/025_approval_decision_evidence.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	auditDown, err := os.ReadFile("../../../../deploy/sql/026_audit_history.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	auditUp, err := os.ReadFile("../../../../deploy/sql/026_audit_history.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	fingerprintDown, err := os.ReadFile("../../../../deploy/sql/027_approval_evidence_fingerprints.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	fingerprintUp, err := os.ReadFile("../../../../deploy/sql/027_approval_evidence_fingerprints.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("unused", func(t *testing.T) {
		ctx, db := newPostgresIntegrationDatabase(t)
		applyAuditColdExportFixtureMigration(t, ctx, db, "down")
		applyEvidenceExportFixtureMigration(t, ctx, db, "down")
		if _, err := db.DB.ExecContext(ctx, string(fingerprintDown)); err != nil {
			t.Fatal("unused evidence fingerprint migration could not roll back", err)
		}
		if _, err := db.DB.ExecContext(ctx, string(auditDown)); err != nil {
			t.Fatal("unused audit history migration could not roll back", err)
		}
		if _, err := db.DB.ExecContext(ctx, string(evidenceDown)); err != nil {
			t.Fatal("unused evidence migration could not roll back", err)
		}
		if _, err := db.DB.ExecContext(ctx, string(importDown)); err != nil {
			t.Fatal("unused import migration could not roll back", err)
		}
		if _, err := db.DB.ExecContext(ctx, string(newerDown)); err != nil {
			t.Fatal("unused export migration could not roll back", err)
		}
		if _, err := db.DB.ExecContext(ctx, string(down)); err != nil {
			t.Fatal("unused migration could not roll back", err)
		}
		if _, err := db.DB.ExecContext(ctx, string(up)); err != nil {
			t.Fatal("migration could not be reapplied", err)
		}
		if _, err := db.DB.ExecContext(ctx, string(newerUp)); err != nil {
			t.Fatal("export migration could not be reapplied", err)
		}
		if _, err := db.DB.ExecContext(ctx, string(importUp)); err != nil {
			t.Fatal("import migration could not be reapplied", err)
		}
		if _, err := db.DB.ExecContext(ctx, string(evidenceUp)); err != nil {
			t.Fatal("evidence migration could not be reapplied", err)
		}
		if _, err := db.DB.ExecContext(ctx, string(auditUp)); err != nil {
			t.Fatal("audit history migration could not be reapplied", err)
		}
		if _, err := db.DB.ExecContext(ctx, string(fingerprintUp)); err != nil {
			t.Fatal("evidence fingerprint migration could not be reapplied", err)
		}
		applyEvidenceExportFixtureMigration(t, ctx, db, "up")
		applyAuditColdExportFixtureMigration(t, ctx, db, "up")
		var exists bool
		if err := db.DB.QueryRowContext(ctx, `select to_regclass('control_event_ack_archive') is not null`).Scan(&exists); err != nil || !exists {
			t.Fatal("reapplied migration lacks acknowledgement history", err)
		}
	})
	t.Run("recovery-history", func(t *testing.T) {
		ctx, db := newPostgresIntegrationDatabase(t)
		if _, err := db.QuarantineRecovery(ctx, approvalTestUUID(t), OriginalDatabaseEpoch, approvalTestUUID(t)); err != nil {
			t.Fatal(err)
		}
		connection, err := db.DB.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		if _, err := connection.ExecContext(ctx, string(down)); err == nil {
			t.Fatal("rollback removed protection after recovery")
		}
		if _, err := connection.ExecContext(ctx, `rollback`); err != nil {
			t.Fatal(err)
		}
	})
}

func TestControlArchiveHistoryRequiresExplicitDatabasePrivileges(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	archiveFixtureEvent(t, ctx, db.DB, "device.revoked", "2000-01-01T00:00:00Z", "2000-01-02T00:00:00Z")
	if result, err := db.ArchiveControlEvents(ctx, archiveFixtureRequest(t)); err != nil || result.Events != 1 {
		t.Fatal("archive setup failed", err)
	}
	// This role exists only in the disposable test cluster and is removed before
	// its database closes. Its identifier contains generated hexadecimal only.
	role := "dsh_archive_test_" + strings.ReplaceAll(approvalTestUUID(t), "-", "")
	if _, err := db.DB.ExecContext(ctx, "create role "+role+" nologin"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := db.DB.ExecContext(cleanup, "drop owned by "+role); err != nil {
			t.Error("fixture role grants were not removed", err)
			return
		}
		if _, err := db.DB.ExecContext(cleanup, "drop role "+role); err != nil {
			t.Error("fixture role was not removed", err)
		}
	})
	if _, err := db.DB.ExecContext(ctx, "grant usage on schema public to "+role); err != nil {
		t.Fatal(err)
	}
	queryAsRole := func(query string, args ...any) error {
		t.Helper()
		tx, err := db.DB.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if _, err := tx.ExecContext(ctx, "set local role "+role); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, query, args...)
		return err
	}
	if err := queryAsRole(`select count(*) from control_outbox_archive`); err == nil {
		t.Fatal("ungranted role read archived event metadata")
	}
	if _, err := db.DB.ExecContext(ctx, "grant select (event_id,database_epoch,batch_epoch,reason) on control_outbox_archive to "+role); err != nil {
		t.Fatal(err)
	}
	if err := queryAsRole(`select event_id,database_epoch,batch_epoch,reason from control_outbox_archive`); err != nil {
		t.Fatal("explicit read grant failed", err)
	}
	for _, query := range []string{`select source from control_outbox_archive`, `select count(*) from control_event_ack_archive`, `select count(*) from control_archive_batches`, `delete from control_outbox_archive`} {
		if err := queryAsRole(query); err == nil {
			t.Fatal("read-only role acquired broader history authority")
		}
	}
	consumer, err := db.NewControlConsumer(ctx, controlNodeA)
	if err != nil {
		t.Fatal(err)
	}
	id := archiveFixtureEvent(t, ctx, db.DB, "device.revoked", "2000-01-01T00:00:00Z", "2000-01-02T00:00:00Z")
	if err := consumer.MarkControlEventPublished(ctx, id); err != nil {
		t.Fatal(err)
	}
	for _, grant := range []string{"grant select,delete on control_event_acks to " + role, "grant select on control_outbox to " + role,
		"grant select on remote_recovery_state to " + role, "grant update(slot) on remote_recovery_state to " + role} {
		if _, err := db.DB.ExecContext(ctx, grant); err != nil {
			t.Fatal(err)
		}
	}
	if err := queryAsRole(`delete from control_event_acks where event_id=$1`, id); err != nil {
		t.Fatal("normal current-epoch acknowledgement compaction required private archive payload access", err)
	}
}

func TestControlArchiveRetentionChecksUseUTCWhilstSessionTimeZoneChanges(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	id := archiveFixtureEvent(t, ctx, db.DB, "device.revoked", "2000-01-01T00:00:00Z", "2000-01-02T00:00:00Z")
	batch := approvalTestUUID(t)
	tx, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `set local time zone 'America/New_York'`); err != nil {
		t.Fatal(err)
	}
	// This instant falls before a DST transition in 2025, but after it in 2026.
	// A session-local +1 year would differ by one hour from the UTC deadline.
	archived := time.Date(2025, time.November, 2, 5, 30, 0, 0, time.UTC)
	retained := time.Date(2026, time.November, 2, 5, 30, 0, 0, time.UTC)
	if _, err := tx.ExecContext(ctx, `insert into control_archive_batches(id,database_epoch,batch_limit,cutoff,archived_at,retain_until,event_count,previous_epoch_count)
	 values($1,$2,1,$3::timestamptz-interval '2160 hours',$3,$4,1,0)`, batch, OriginalDatabaseEpoch, archived, retained); err != nil {
		t.Fatal("batch retention depended on session timezone", err)
	}
	if _, err := tx.ExecContext(ctx, `insert into control_outbox_archive(event_id,batch_id,batch_epoch,database_epoch,topic,source_created_at,source,reason,archived_at,retain_until)
	 select e.id,$2,$3,e.database_epoch,e.topic,e.created_at,to_jsonb(e),'covered',$4,$5 from control_outbox e where e.id=$1`, id, batch, OriginalDatabaseEpoch, archived, retained); err != nil {
		t.Fatal("event retention depended on session timezone", err)
	}
	if _, err := tx.ExecContext(ctx, `delete from control_outbox where id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var valid bool
	if err := db.DB.QueryRowContext(ctx, `select retain_until=((archived_at at time zone 'UTC')+interval '1 year') at time zone 'UTC' from control_outbox_archive where event_id=$1`, id).Scan(&valid); err != nil || !valid {
		t.Fatal("UTC retention changed after commit", err)
	}
}

func TestControlArchiveExpiredDeletionRequiresCommittedAudit(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	id := archiveFixtureEvent(t, ctx, db.DB, "device.revoked", "2000-01-01T00:00:00Z", "2000-01-02T00:00:00Z")
	batch := approvalTestUUID(t)
	var archived, cutoff, retained time.Time
	if err := db.DB.QueryRowContext(ctx, `with moment as materialized(select clock_timestamp()-interval '2 years' as at)
	 select at,at-interval '90 days',at+interval '1 year' from moment`).Scan(&archived, &cutoff, &retained); err != nil {
		t.Fatal(err)
	}
	tx, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `insert into control_archive_batches(id,database_epoch,batch_limit,cutoff,archived_at,retain_until,event_count,previous_epoch_count)
	 values($1,$2,1,$3,$4,$5,1,0)`, batch, OriginalDatabaseEpoch, cutoff, archived, retained); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `insert into control_outbox_archive(event_id,batch_id,batch_epoch,database_epoch,topic,source_created_at,source,reason,archived_at,retain_until)
	 select e.id,$2,$3,e.database_epoch,e.topic,e.created_at,to_jsonb(e),'covered',$4,$5 from control_outbox e where e.id=$1`, id, batch, OriginalDatabaseEpoch, archived, retained); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `with moment as materialized(select clock_timestamp() as at)
	 insert into control_event_ack_archive(node_id,event_id,applied_at,source)
	 select $1::uuid,$2::uuid,at,jsonb_build_object('node_id',$1::uuid,'event_id',$2::uuid,'applied_at',at) from moment`, controlNodeA, id); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `delete from control_outbox where id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `delete from control_event_ack_archive where event_id=$1`, id); err == nil {
		t.Fatal("acknowledgement was deleted independently of its parent")
	}
	epoch, operation := approvalTestUUID(t), approvalTestUUID(t)
	if _, err := db.QuarantineRecovery(ctx, operation, OriginalDatabaseEpoch, epoch); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `delete from control_outbox_archive where event_id=$1`, id); err == nil {
		t.Fatal("quarantined recovery allowed archive deletion")
	}
	manifest := RecoveryAuthority{Version: 1, Complete: true, RecoveryID: operation, DatabaseEpoch: epoch, Issuer: "https://id.example.edu", CapturedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Minute).UTC(), Users: []RecoveryUser{}}
	if _, err := db.ReleaseRecovery(ctx, epoch, manifest.Issuer, manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `create function fixture_archive_delete_failure() returns trigger language plpgsql as $$ begin if new.action='control.archive.delete' then raise exception 'PRIVATE_ARCHIVE_AUDIT_FAILURE';end if;return null;end $$;
	 create constraint trigger fixture_archive_delete_failure after insert on audit_log deferrable initially deferred for each row execute function fixture_archive_delete_failure()`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `delete from control_outbox_archive where event_id=$1`, id); err == nil {
		t.Fatal("expired archive was deleted without a committed audit")
	}
	var records, audits, archivedAcks int
	if err := db.DB.QueryRowContext(ctx, `select (select count(*) from control_outbox_archive),(select count(*) from audit_log where action='control.archive.delete'),(select count(*) from control_event_ack_archive)`).Scan(&records, &audits, &archivedAcks); err != nil || records != 1 || audits != 0 || archivedAcks != 1 {
		t.Fatal("failed delete did not roll back", records, audits, archivedAcks, err)
	}
	if _, err := db.DB.ExecContext(ctx, `drop trigger fixture_archive_delete_failure on audit_log`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `delete from control_outbox_archive where event_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.QueryRowContext(ctx, `select count(*) from control_event_ack_archive`).Scan(&archivedAcks); err != nil || archivedAcks != 0 {
		t.Fatal("audited parent expiry did not retire its acknowledgement", archivedAcks, err)
	}
	var correct bool
	if err := db.DB.QueryRowContext(ctx, `select actor_id=current_user and metadata->>'db_session_user'=session_user and metadata->>'event_id'=$1 and metadata->>'batch_id'=$2
	 and not (metadata ? 'payload') from audit_log where action='control.archive.delete'`, id, batch).Scan(&correct); err != nil || !correct {
		t.Fatal("expiry delete audit lacks its DB actor and fixed metadata", err)
	}
}

func TestControlArchiveSourceDeletionRequiresExactEventAndAcknowledgementCopies(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	consumer, err := db.NewControlConsumer(ctx, controlNodeA)
	if err != nil {
		t.Fatal(err)
	}
	id := archiveFixtureEvent(t, ctx, db.DB, "device.revoked", "2000-01-01T00:00:00Z", "2000-01-02T00:00:00Z")
	if err := consumer.MarkControlEventPublished(ctx, id); err != nil {
		t.Fatal(err)
	}
	for _, altered := range []bool{false, true} {
		tx, err := db.DB.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		batch := approvalTestUUID(t)
		_, err = tx.ExecContext(ctx, `with moment as materialized(select clock_timestamp() as at)
		 insert into control_outbox_archive(event_id,batch_id,batch_epoch,database_epoch,topic,source_created_at,source,reason,archived_at,retain_until)
		 select e.id,$2,$3,e.database_epoch,e.topic,e.created_at,
		 case when $4 then to_jsonb(e)||'{"unexpected":"changed"}'::jsonb else to_jsonb(e) end,
		 'covered',at,((at at time zone 'UTC')+interval '1 year') at time zone 'UTC' from control_outbox e cross join moment where e.id=$1`, id, batch, OriginalDatabaseEpoch, altered)
		if err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		if altered {
			if _, err := tx.ExecContext(ctx, `insert into control_event_ack_archive(node_id,event_id,applied_at,source)
			 select a.node_id,a.event_id,a.applied_at,to_jsonb(a) from control_event_acks a where a.event_id=$1`, id); err != nil {
				_ = tx.Rollback()
				t.Fatal(err)
			}
		}
		// The first case omits an acknowledgement; the second copies all acks
		// but alters the original event. Either prevents source removal.
		if _, err = tx.ExecContext(ctx, `delete from control_outbox where id=$1`, id); err == nil {
			_ = tx.Rollback()
			t.Fatal("incomplete archive allowed source deletion", altered)
		}
		if err := tx.Rollback(); err != nil {
			t.Fatal(err)
		}
	}
	var hot, acks, cold int
	if err := db.DB.QueryRowContext(ctx, `select (select count(*) from control_outbox where id=$1),
	 (select count(*) from control_event_acks where event_id=$1),(select count(*) from control_outbox_archive where event_id=$1)`, id).Scan(&hot, &acks, &cold); err != nil || hot != 1 || acks != 1 || cold != 0 {
		t.Fatal("failed copy changed source history", hot, acks, cold, err)
	}
	result, err := db.ArchiveControlEvents(ctx, archiveFixtureRequest(t))
	if err != nil || result.Events != 1 {
		t.Fatal("complete transactional copy could not proceed", result, err)
	}
}

func TestControlArchiveAcrossActualRestorePreservesHistoryAndEpochProvenance(t *testing.T) {
	ctx, source := newPostgresIntegrationDatabase(t)
	consumer, err := source.NewControlConsumer(ctx, controlNodeA)
	if err != nil {
		t.Fatal(err)
	}
	ephemeral, err := source.NewControlConsumer(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	first := archiveFixtureEvent(t, ctx, source.DB, "device.revoked", "2000-01-01T00:00:00Z", "2000-01-02T00:00:00Z")
	second := archiveFixtureEvent(t, ctx, source.DB, "device.revoked", "2000-01-01T00:00:00Z", "")
	for _, node := range []*ControlConsumer{consumer, ephemeral} {
		for _, event := range []string{first, second} {
			if err := node.MarkControlEventPublished(ctx, event); err != nil {
				t.Fatal(err)
			}
		}
	}
	original := archiveFixtureRequest(t)
	firstBatch, err := source.ArchiveControlEvents(ctx, original)
	if err != nil || firstBatch.Events != 1 {
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
	current, err := restored.NewControlConsumer(restoredCtx, controlNodeA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(restoredCtx, `update control_consumers set lease_until=clock_timestamp()-interval '20 minutes' where node_id=$1`, ephemeral.node); err != nil {
		t.Fatal(err)
	}
	if err := current.PruneEphemeral(restoredCtx); err != nil {
		t.Fatal(err)
	}
	var oldNode, oldAcks int
	if err := database.QueryRowContext(restoredCtx, `select (select count(*) from control_consumers where node_id=$1),(select count(*) from control_event_acks where event_id=$2)`, ephemeral.node, second).Scan(&oldNode, &oldAcks); err != nil || oldNode != 1 || oldAcks != 2 {
		t.Fatal("cleanup discarded old-epoch acknowledgements before archival", oldNode, oldAcks, err)
	}
	if _, err := database.ExecContext(restoredCtx, `delete from control_event_acks where event_id=$1`, second); err == nil {
		t.Fatal("direct deletion discarded unarchived old-epoch acknowledgements")
	}
	if _, err := database.ExecContext(restoredCtx, `delete from control_consumers where node_id=$1`, ephemeral.node); err == nil {
		t.Fatal("direct consumer deletion discarded old-epoch acknowledgements")
	}
	changed := original
	changed.DatabaseEpoch = epoch
	if _, err := restored.ArchiveControlEvents(restoredCtx, changed); !errors.Is(err, ErrControlArchiveConflict) {
		t.Fatal("old completed operation was rebound to restored history", err)
	}
	request := archiveFixtureRequest(t)
	request.DatabaseEpoch = epoch
	result, err := restored.ArchiveControlEvents(restoredCtx, request)
	if err != nil || result.Events != 1 || result.PreviousEpochEvents != 1 {
		t.Fatal("old unconsumed provenance was lost after real restore", result, err)
	}
	if err := current.PruneEphemeral(restoredCtx); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(restoredCtx, `select (select count(*) from control_consumers where node_id=$1),
	 (select count(*) from control_event_ack_archive where event_id in ($2,$3))`, ephemeral.node, first, second).Scan(&oldNode, &oldAcks); err != nil || oldNode != 0 || oldAcks != 4 {
		t.Fatal("old acknowledgements did not survive consumer retirement", oldNode, oldAcks, err)
	}
	var preserved int
	if err := database.QueryRowContext(restoredCtx, `select count(*) from control_outbox_archive where event_id in ($1,$2) and database_epoch=$3`, first, second, OriginalDatabaseEpoch).Scan(&preserved); err != nil || preserved != 2 {
		t.Fatal("archive lost original source identities", preserved, err)
	}
	fresh := archiveFixtureEvent(t, restoredCtx, database, "device.revoked", "2000-01-01T00:00:00Z", "2000-01-02T00:00:00Z")
	request.BatchID = approvalTestUUID(t)
	result, err = restored.ArchiveControlEvents(restoredCtx, request)
	if err != nil || result.Events != 0 {
		t.Fatal("current event was mistaken for old recovered XID", result, err)
	}
	if !consumerPendingIDs(t, restoredCtx, current, 128)[fresh] {
		t.Fatal("restored current consumer missed its new source event")
	}
	if err := current.MarkControlEventPublished(restoredCtx, fresh); err != nil {
		t.Fatal(err)
	}
	request.BatchID = approvalTestUUID(t)
	result, err = restored.ArchiveControlEvents(restoredCtx, request)
	if err != nil || result.Events != 1 || result.PreviousEpochEvents != 0 {
		t.Fatal("current acknowledgement could not retire its source", result, err)
	}
}

func TestControlArchiveLegacySQLBootstrapCapturesCoverageAfterMaintenance(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	// Four concurrent transactions intentionally wait on each other; reserve one
	// connection to observe their PostgreSQL lock state without blocking on pool admission.
	db.DB.SetMaxOpenConns(5)
	producer, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer producer.Rollback()
	id := archiveFixtureEvent(t, ctx, producer, "device.revoked", "2000-01-01T00:00:00Z", "2000-01-02T00:00:00Z")
	var xid string
	if err := producer.QueryRowContext(ctx, `select producer_xid::text from control_outbox where id=$1`, id).Scan(&xid); err != nil {
		t.Fatal(err)
	}
	hold, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Rollback()
	if _, err := hold.ExecContext(ctx, `select epoch from remote_recovery_state where slot=1 for update`); err != nil {
		t.Fatal(err)
	}
	request := archiveFixtureRequest(t)
	type archivedResult struct {
		result ControlArchiveResult
		err    error
	}
	archived := make(chan archivedResult, 1)
	go func() { result, err := db.ArchiveControlEvents(ctx, request); archived <- archivedResult{result, err} }()
	wait := func(query string) {
		t.Helper()
		deadline := time.Now().Add(500 * time.Millisecond)
		for {
			var ready bool
			if err := db.DB.QueryRowContext(ctx, query).Scan(&ready); err != nil {
				t.Fatal(err)
			}
			if ready {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("fixture did not reach its authoritative lock wait")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	wait(`select exists(select 1 from pg_stat_activity where datname=current_database() and wait_event_type='Lock' and query like 'select epoch::text,phase%')`)
	registered := make(chan error, 1)
	generation := approvalTestUUID(t)
	go func() {
		_, err := db.DB.ExecContext(ctx, `insert into control_consumers(node_id,generation,coverage,durable,lease_until)
	 values($1,$2,pg_current_snapshot(),true,clock_timestamp()+interval '10 seconds')`, controlNodeA, generation)
		registered <- err
	}()
	wait(`select exists(select 1 from pg_stat_activity where datname=current_database() and wait_event='advisory' and query like 'insert into control_consumers%')`)
	if err := producer.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := hold.Rollback(); err != nil {
		t.Fatal(err)
	}
	result := <-archived
	if result.err != nil || result.result.Events != 1 {
		t.Fatal("archive did not finish before waiting legacy registration", result)
	}
	if err := <-registered; err != nil {
		t.Fatal(err)
	}
	var current bool
	if err := db.DB.QueryRowContext(ctx, `select pg_visible_in_snapshot($2::xid8,coverage) and database_epoch=$3 from control_consumers where node_id=$1`, controlNodeA, xid, OriginalDatabaseEpoch).Scan(&current); err != nil || !current {
		t.Fatal("legacy INSERT retained its pre-wait transaction snapshot", current, err)
	}
}

func TestControlArchiveRetiresOnlyReleasedOldEpochWithoutReusingSnapshots(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	id := archiveFixtureEvent(t, ctx, db.DB, "device.revoked", "2000-01-01T00:00:00Z", "")
	consumer, err := db.NewControlConsumer(ctx, controlNodeA)
	if err != nil {
		t.Fatal(err)
	}
	epoch, operation := approvalTestUUID(t), approvalTestUUID(t)
	if _, err := db.QuarantineRecovery(ctx, operation, OriginalDatabaseEpoch, epoch); err != nil {
		t.Fatal(err)
	}
	request := archiveFixtureRequest(t)
	request.DatabaseEpoch = epoch
	if _, err := db.ArchiveControlEvents(ctx, request); !errors.Is(err, ErrRecoveryUnavailable) {
		t.Fatal("quarantined database archived authority history", err)
	}
	// No identities are provisioned in this metadata-only fixture; a complete
	// current snapshot is explicitly empty and supplied after quarantine.
	manifest := RecoveryAuthority{Version: 1, Complete: true, RecoveryID: operation, DatabaseEpoch: epoch, Issuer: "https://id.example.edu", CapturedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Minute).UTC(), Users: []RecoveryUser{}}
	if _, err := db.ReleaseRecovery(ctx, epoch, manifest.Issuer, manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ArchiveControlEvents(ctx, archiveFixtureRequest(t)); !errors.Is(err, ErrRecoveryUnavailable) {
		t.Fatal("old deployment epoch performed maintenance", err)
	}
	result, err := db.ArchiveControlEvents(ctx, request)
	if err != nil || result.Events != 1 || result.PreviousEpochEvents != 1 {
		t.Fatal("fenced old epoch was reinterpreted as live replay", result, err)
	}
	if err := consumer.MarkControlEventPublished(ctx, id); !errors.Is(err, ErrRecoveryUnavailable) {
		t.Fatal("old consumer acknowledged new history", err)
	}
	current, err := db.NewControlConsumer(ctx, controlNodeA)
	if err != nil {
		t.Fatal(err)
	}
	if err := current.MarkControlEventPublished(ctx, id); !errors.Is(err, ErrGrantInvalid) {
		t.Fatal("old archived event masqueraded as current apply", err)
	}
	var original bool
	if err := db.DB.QueryRowContext(ctx, `select database_epoch=$2 and batch_epoch=$3 and reason='recovered_epoch' and source->'published_at'='null'::jsonb from control_outbox_archive where event_id=$1`, id, OriginalDatabaseEpoch, epoch).Scan(&original); err != nil || !original {
		t.Fatal("old provenance was not preserved", err)
	}
}
