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

type auditFixtureDB interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// Production timestamps are database-controlled. Only the disposable fixture
// installs a later trigger to model records aged by the passage of time.
func enableAuditFixtureTime(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	if _, err := db.ExecContext(ctx, `create function test_audit_fixture_time() returns trigger language plpgsql as $$
	 begin new.ts=(new.metadata->>'fixture_time')::timestamptz; new.metadata=new.metadata-'fixture_time'; return new; end $$;
	 create trigger zz_audit_fixture_time before insert on audit_log for each row when(new.actor_id='fixture') execute function test_audit_fixture_time()`); err != nil {
		t.Fatal(err)
	}
}

func auditFixtureEntry(t *testing.T, ctx context.Context, db auditFixtureDB, at, marker string) int64 {
	t.Helper()
	var id int64
	if err := db.QueryRowContext(ctx, `insert into audit_log(ts,actor_type,actor_id,action,result,metadata)
	 values($1::timestamptz,'system','fixture','fixture.event','success',jsonb_build_object('marker',$2::text,'fixture_time',$1::text)) returning id`, at, marker).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func auditArchiveFixtureRequest(t *testing.T) AuditArchiveRequest {
	t.Helper()
	return AuditArchiveRequest{BatchID: approvalTestUUID(t), DatabaseEpoch: OriginalDatabaseEpoch, Limit: 64, RetentionYears: 1}
}

func TestAuditArchiveMovesOnlyOldRowsAndReconcilesSameBatch(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	enableAuditFixtureTime(t, ctx, db.DB)
	old := auditFixtureEntry(t, ctx, db.DB, "2000-01-01T00:00:00Z", "PRIVATE_AUDIT_SOURCE")
	recent := auditFixtureEntry(t, ctx, db.DB, time.Now().UTC().Format(time.RFC3339Nano), "recent")
	var stamped time.Time
	var stampedEpoch string
	if err := db.DB.QueryRowContext(ctx, `insert into audit_log(ts,database_epoch,actor_type,actor_id,action,result)
	 values('2000-01-01','ffffffff-ffff-4fff-8fff-ffffffffffff','system','untrusted','fixture.stamped','success') returning ts,database_epoch::text`).Scan(&stamped, &stampedEpoch); err != nil || stamped.Before(time.Now().Add(-time.Minute)) || stampedEpoch != OriginalDatabaseEpoch {
		t.Fatal("a caller forged the timestamp or epoch of a new audit record", err)
	}
	var source string
	if err := db.DB.QueryRowContext(ctx, `select to_jsonb(a)::text from audit_log a where id=$1`, old).Scan(&source); err != nil {
		t.Fatal(err)
	}
	request := auditArchiveFixtureRequest(t)
	result, err := db.ArchiveAuditHistory(ctx, request)
	if err != nil || result.Entries != 1 || result.BatchID != request.BatchID {
		t.Fatal("audit archive failed", err)
	}
	var exact bool
	var oldHot, recentHot, audits int
	if err := db.DB.QueryRowContext(ctx, `select (select source=$2::jsonb from audit_log_archive where source_id=$1),
	 (select count(*) from audit_log where id=$1),(select count(*) from audit_log where id=$3),
	 (select count(*) from audit_log where action='audit.archive.batch' and metadata->>'batch_id'=$4)`, old, source, recent, request.BatchID).
		Scan(&exact, &oldHot, &recentHot, &audits); err != nil || !exact || oldHot != 0 || recentHot != 1 || audits != 1 {
		t.Fatal("audit archive did not atomically preserve the source", oldHot, recentHot, audits, err)
	}
	again, err := db.ArchiveAuditHistory(ctx, request)
	if err != nil || !again.ArchivedAt.Equal(result.ArchivedAt) || again.Entries != 1 {
		t.Fatal("batch retry was not stable", err)
	}
	changed := request
	changed.Limit++
	if _, err := db.ArchiveAuditHistory(ctx, changed); !errors.Is(err, ErrAuditArchiveConflict) {
		t.Fatal("batch UUID was rebound", err)
	}
	var exposed bool
	if err := db.DB.QueryRowContext(ctx, `select metadata::text like '%PRIVATE_AUDIT_SOURCE%' from audit_log where action='audit.archive.batch'`).Scan(&exposed); err != nil || exposed {
		t.Fatal("archive audit included source content", err)
	}
	for _, statement := range []string{
		`update audit_log set action='changed'`,
		`delete from audit_log`,
		`truncate audit_log`,
		`update audit_log_archive set source='{}'::jsonb`,
		`delete from audit_log_archive`,
		`truncate audit_log_archive`,
		`delete from audit_archive_batches`,
	} {
		if _, err := db.DB.ExecContext(ctx, statement); err == nil {
			t.Fatal("protected audit history was modified")
		}
	}
}

func TestAuditArchiveRejectsOversizedRowsAndRollsBackAuditFailure(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	enableAuditFixtureTime(t, ctx, db.DB)
	id := auditFixtureEntry(t, ctx, db.DB, "2000-01-01T00:00:00Z", strings.Repeat("x", maxAuditArchiveEntry))
	request := auditArchiveFixtureRequest(t)
	if _, err := db.ArchiveAuditHistory(ctx, request); !errors.Is(err, ErrAuditArchiveTooLarge) {
		t.Fatal("oversized audit source was not refused", err)
	}
	var hot, batches int
	if err := db.DB.QueryRowContext(ctx, `select (select count(*) from audit_log where id=$1),(select count(*) from audit_archive_batches)`, id).Scan(&hot, &batches); err != nil || hot != 1 || batches != 0 {
		t.Fatal("oversized audit source was changed", hot, batches, err)
	}
	// A separate database supplies a normal row for the audit sink failure.
	ctx, db = newPostgresIntegrationDatabase(t)
	enableAuditFixtureTime(t, ctx, db.DB)
	id = auditFixtureEntry(t, ctx, db.DB, "2000-01-01T00:00:00Z", "source")
	request = auditArchiveFixtureRequest(t)
	if _, err := db.DB.ExecContext(ctx, `create function test_fail_audit_archive() returns trigger language plpgsql as $$
	 begin if new.action='audit.archive.batch' then raise exception 'fixture failure'; end if; return new; end $$;
	 create trigger test_fail_audit_archive before insert on audit_log for each row execute function test_fail_audit_archive()`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ArchiveAuditHistory(ctx, request); !errors.Is(err, ErrDatabaseUnavailable) {
		t.Fatal("archive ignored its audit failure", err)
	}
	var history int
	if err := db.DB.QueryRowContext(ctx, `select (select count(*) from audit_log where id=$1),(select count(*) from audit_archive_batches),(select count(*) from audit_log_archive)`, id).
		Scan(&hot, &batches, &history); err != nil || hot != 1 || batches != 0 || history != 0 {
		t.Fatal("audit failure left a partial archive", hot, batches, history, err)
	}
	if _, err := db.DB.ExecContext(ctx, `drop trigger test_fail_audit_archive on audit_log; drop function test_fail_audit_archive();
	 create function test_fail_audit_archive_commit() returns trigger language plpgsql as $$
	 begin if new.action='audit.archive.batch' then raise exception 'fixture deferred failure'; end if; return null; end $$;
	 create constraint trigger test_fail_audit_archive_commit after insert on audit_log deferrable initially deferred
	 for each row execute function test_fail_audit_archive_commit()`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ArchiveAuditHistory(ctx, request); !errors.Is(err, ErrDatabaseUnavailable) {
		t.Fatal("archive ignored its deferred audit failure", err)
	}
	var audits int
	if err := db.DB.QueryRowContext(ctx, `select (select count(*) from audit_log where id=$1),(select count(*) from audit_archive_batches),
	 (select count(*) from audit_log_archive),(select count(*) from audit_log where action='audit.archive.batch')`, id).
		Scan(&hot, &batches, &history, &audits); err != nil || hot != 1 || batches != 0 || history != 0 || audits != 0 {
		t.Fatal("deferred audit failure left a partial archive", hot, batches, history, audits, err)
	}
}

func TestAuditArchiveRetainsLateCommitsAndSkipsLockedRows(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	enableAuditFixtureTime(t, ctx, db.DB)
	producer, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer producer.Rollback()
	late := auditFixtureEntry(t, ctx, producer, "2000-01-01T00:00:00Z", "late")
	request := auditArchiveFixtureRequest(t)
	result, err := db.ArchiveAuditHistory(ctx, request)
	if err != nil || result.Entries != 0 {
		t.Fatal("uncommitted audit was treated as visible", err)
	}
	if err := producer.Commit(); err != nil {
		t.Fatal(err)
	}
	other := auditFixtureEntry(t, ctx, db.DB, "2000-01-02T00:00:00Z", "other")
	lock, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback()
	if _, err := lock.ExecContext(ctx, `select id from audit_log where id=$1 for update`, late); err != nil {
		t.Fatal(err)
	}
	request.BatchID, request.Limit = approvalTestUUID(t), 1
	result, err = db.ArchiveAuditHistory(ctx, request)
	if err != nil || result.Entries != 1 {
		t.Fatal("locked source prevented other old rows from moving", err)
	}
	var copied bool
	if err := db.DB.QueryRowContext(ctx, `select exists(select 1 from audit_log_archive where source_id=$1)`, other).Scan(&copied); err != nil || !copied {
		t.Fatal("wrong source was selected while another was locked", err)
	}
	if err := lock.Rollback(); err != nil {
		t.Fatal(err)
	}
	request.BatchID = approvalTestUUID(t)
	result, err = db.ArchiveAuditHistory(ctx, request)
	if err != nil || result.Entries != 1 {
		t.Fatal("late commit or unlocked source was lost", err)
	}
	if err := db.DB.QueryRowContext(ctx, `select exists(select 1 from audit_log_archive where source_id=$1)`, late).Scan(&copied); err != nil || !copied {
		t.Fatal("late-committing audit was lost", err)
	}
}

func TestAuditArchiveConcurrentRetriesCommitOneBatch(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	enableAuditFixtureTime(t, ctx, db.DB)
	auditFixtureEntry(t, ctx, db.DB, "2000-01-01T00:00:00Z", "source")
	request := auditArchiveFixtureRequest(t)
	type outcome struct {
		result AuditArchiveResult
		err    error
	}
	results := make(chan outcome, 4)
	var group sync.WaitGroup
	for range 4 {
		group.Go(func() {
			result, err := db.ArchiveAuditHistory(ctx, request)
			results <- outcome{result, err}
		})
	}
	group.Wait()
	close(results)
	var first AuditArchiveResult
	for item := range results {
		if item.err != nil {
			t.Fatal(item.err)
		}
		if first.BatchID == "" {
			first = item.result
		} else if item.result.Entries != first.Entries || !item.result.ArchivedAt.Equal(first.ArchivedAt) {
			t.Fatal("concurrent retry changed its batch")
		}
	}
	var batches, history, audits int
	if err := db.DB.QueryRowContext(ctx, `select (select count(*) from audit_archive_batches),
	 (select count(*) from audit_log_archive),(select count(*) from audit_log where action='audit.archive.batch')`).Scan(&batches, &history, &audits); err != nil || batches != 1 || history != 1 || audits != 1 {
		t.Fatal("concurrent retries duplicated audit history", batches, history, audits, err)
	}
}

func TestAuditArchiveRejectsIncompleteBatchAndLateAppend(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	enableAuditFixtureTime(t, ctx, db.DB)
	old := auditFixtureEntry(t, ctx, db.DB, "2000-01-01T00:00:00Z", "source")
	request := auditArchiveFixtureRequest(t)
	result, err := db.ArchiveAuditHistory(ctx, request)
	if err != nil || result.Entries != 1 {
		t.Fatal(err)
	}
	second := auditFixtureEntry(t, ctx, db.DB, "2000-01-02T00:00:00Z", "second")
	if _, err := db.DB.ExecContext(ctx, `insert into audit_log_archive(source_id,batch_id,batch_epoch,source_epoch,source_ts,source)
	 select a.id,$2,$3,a.database_epoch,a.ts,to_jsonb(a) from audit_log a where a.id=$1`, second, request.BatchID, request.DatabaseEpoch); err == nil {
		t.Fatal("committed batch acquired a late event")
	}
	if _, err := db.DB.ExecContext(ctx, `insert into audit_archive_batches(id,database_epoch,batch_limit,retention_years,cutoff,archived_at,retain_until,entry_count)
	 select $1,database_epoch,batch_limit,retention_years,cutoff,archived_at,retain_until,0 from audit_archive_batches where id=$2`, approvalTestUUID(t), request.BatchID); err == nil {
		t.Fatal("batch committed without an operation audit")
	}
	var first, remaining int
	if err := db.DB.QueryRowContext(ctx, `select (select count(*) from audit_log_archive where source_id=$1),(select count(*) from audit_log where id=$2)`, old, second).Scan(&first, &remaining); err != nil || first != 1 || remaining != 1 {
		t.Fatal("failed late append changed history", first, remaining, err)
	}
}

func TestAuditArchiveBatchCannotForgeRetentionClock(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	tx, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var guarded bool
	if err := tx.QueryRowContext(ctx, `insert into audit_archive_batches(id,database_epoch,batch_limit,retention_years,cutoff,archived_at,retain_until,entry_count)
	 values($1,$2,1,1,'2100-01-01','2101-01-01','2102-01-01',0)
	 returning archived_at<=clock_timestamp() and cutoff<=clock_timestamp()-interval '2160 hours'
	   and retain_until>=((archived_at at time zone 'UTC')+interval '1 year') at time zone 'UTC'`, approvalTestUUID(t), OriginalDatabaseEpoch).Scan(&guarded); err != nil || !guarded {
		t.Fatal("batch accepted caller-supplied retention times", err)
	}
}

func TestAuditArchiveLegacyEpochIsUnknownAndRecoveryPreservesIt(t *testing.T) {
	ctx, source := newPostgresIntegrationDatabase(t)
	fingerprintDown, err := os.ReadFile("../../../../deploy/sql/027_approval_evidence_fingerprints.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	fingerprintUp, err := os.ReadFile("../../../../deploy/sql/027_approval_evidence_fingerprints.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("../../../../deploy/sql/026_audit_history.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, err := os.ReadFile("../../../../deploy/sql/026_audit_history.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.DB.ExecContext(ctx, string(fingerprintDown)); err != nil {
		t.Fatal(err)
	}
	if _, err := source.DB.ExecContext(ctx, string(down)); err != nil {
		t.Fatal(err)
	}
	legacy := auditFixtureEntry(t, ctx, source.DB, "2000-01-01T00:00:00Z", "legacy")
	if _, err := source.DB.ExecContext(ctx, string(up)); err != nil {
		t.Fatal(err)
	}
	if _, err := source.DB.ExecContext(ctx, string(fingerprintUp)); err != nil {
		t.Fatal(err)
	}
	enableAuditFixtureTime(t, ctx, source.DB)
	old := auditFixtureEntry(t, ctx, source.DB, "2000-01-02T00:00:00Z", "original-epoch")
	request := auditArchiveFixtureRequest(t)
	request.Limit = 1
	if result, err := source.ArchiveAuditHistory(ctx, request); err != nil || result.Entries != 1 {
		t.Fatal("legacy source could not be archived", err)
	}
	var legacyEpoch sql.NullString
	if err := source.DB.QueryRowContext(ctx, `select source_epoch::text from audit_log_archive where source_id=$1`, legacy).Scan(&legacyEpoch); err != nil || legacyEpoch.Valid {
		t.Fatal("legacy source was assigned an invented epoch", err)
	}
	restoredCtx, database, _ := testsupport.RestoredPostgresDatabase(t, source.DB)
	restored := &Postgres{DB: database}
	epoch, operation := approvalTestUUID(t), approvalTestUUID(t)
	if _, err := restored.QuarantineRecovery(restoredCtx, operation, OriginalDatabaseEpoch, epoch); err != nil {
		t.Fatal(err)
	}
	probe := request
	probe.BatchID, probe.DatabaseEpoch = approvalTestUUID(t), epoch
	if _, err := restored.ArchiveAuditHistory(restoredCtx, probe); !errors.Is(err, ErrRecoveryUnavailable) {
		t.Fatal("archive proceeded during recovery quarantine", err)
	}
	manifest := RecoveryAuthority{Version: 1, Complete: true, RecoveryID: operation, DatabaseEpoch: epoch, Issuer: "https://id.example.edu", CapturedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Minute).UTC(), Users: []RecoveryUser{}}
	if _, err := restored.ReleaseRecovery(restoredCtx, epoch, manifest.Issuer, manifest); err != nil {
		t.Fatal(err)
	}
	changed := request
	changed.DatabaseEpoch = epoch
	if _, err := restored.ArchiveAuditHistory(restoredCtx, changed); !errors.Is(err, ErrAuditArchiveConflict) {
		t.Fatal("old archive operation rebound to new epoch", err)
	}
	changed.BatchID = approvalTestUUID(t)
	if result, err := restored.ArchiveAuditHistory(restoredCtx, changed); err != nil || result.Entries != 1 {
		t.Fatal("old audit source could not be archived after recovery", err)
	}
	var origin, archivedEpoch string
	if err := database.QueryRowContext(restoredCtx, `select source_epoch::text,batch_epoch::text from audit_log_archive where source_id=$1`, old).Scan(&origin, &archivedEpoch); err != nil || origin != OriginalDatabaseEpoch || archivedEpoch != epoch {
		t.Fatal("recovery lost original audit provenance", err)
	}
}

func TestAuditArchiveExpiredDeletionRequiresAuditAndRetainsBatchIdentity(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	enableAuditFixtureTime(t, ctx, db.DB)
	id := auditFixtureEntry(t, ctx, db.DB, "2000-01-01T00:00:00Z", "source")
	request := auditArchiveFixtureRequest(t)
	if _, err := db.ArchiveAuditHistory(ctx, request); err != nil {
		t.Fatal(err)
	}
	// A privileged fixture simulates elapsed retention; ordinary updates fail.
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
	 retain_until=((moment.at at time zone 'UTC')+interval '1 year') at time zone 'UTC' from moment where id=$1`, request.BatchID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `alter table audit_archive_batches enable trigger audit_archive_batch_guard`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `create function test_fail_audit_archive_delete() returns trigger language plpgsql as $$
	 begin if new.action='audit.archive.delete' then raise exception 'fixture failure'; end if; return new; end $$;
	 create trigger test_fail_audit_archive_delete before insert on audit_log for each row execute function test_fail_audit_archive_delete()`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `delete from audit_log_archive where source_id=$1`, id); err == nil {
		t.Fatal("expired deletion ignored audit failure")
	}
	var history int
	if err := db.DB.QueryRowContext(ctx, `select count(*) from audit_log_archive where source_id=$1`, id).Scan(&history); err != nil || history != 1 {
		t.Fatal("failed audit removed archived history", history, err)
	}
	if _, err := db.DB.ExecContext(ctx, `drop trigger test_fail_audit_archive_delete on audit_log; drop function test_fail_audit_archive_delete()`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `delete from audit_log_archive where source_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	var headers, audits int
	if err := db.DB.QueryRowContext(ctx, `select (select count(*) from audit_archive_batches where id=$1),
	 (select count(*) from audit_log where action='audit.archive.delete' and metadata->>'batch_id'=$1::text)`, request.BatchID).Scan(&headers, &audits); err != nil || headers != 1 || audits != 1 {
		t.Fatal("expiration lost batch identity or audit", headers, audits, err)
	}
	result, err := db.ArchiveAuditHistory(ctx, request)
	if err != nil || result.Entries != 1 {
		t.Fatal("expired batch could not be reconciled", err)
	}
	down, err := os.ReadFile("../../../../deploy/sql/026_audit_history.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := db.DB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, string(down)); err == nil {
		t.Fatal("rollback erased retained audit provenance")
	}
	if _, err := conn.ExecContext(ctx, `rollback`); err != nil {
		t.Fatal(err)
	}
}

func TestAuditArchiveRequiresExplicitHistoryPrivileges(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	role := "dsh_audit_history_" + strings.ReplaceAll(approvalTestUUID(t), "-", "")
	if _, err := db.DB.ExecContext(ctx, "create role "+role+" nologin"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := db.DB.ExecContext(cleanup, "drop role "+role); err != nil {
			t.Error("fixture role was not removed", err)
		}
	})
	var metadataRead, sourceRead bool
	if err := db.DB.QueryRowContext(ctx, `select has_table_privilege($1,'audit_archive_batches','select'),has_table_privilege($1,'audit_log_archive','select')`, role).
		Scan(&metadataRead, &sourceRead); err != nil || metadataRead || sourceRead {
		t.Fatal("audit history was exposed without explicit grants", metadataRead, sourceRead, err)
	}
}

func TestAuditArchiveLimitedRoleCannotMutateSourcesOrRecoveryEpoch(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	enableAuditFixtureTime(t, ctx, db.DB)
	id := auditFixtureEntry(t, ctx, db.DB, "2000-01-01T00:00:00Z", "source")
	role := "dsh_audit_archiver_" + strings.ReplaceAll(approvalTestUUID(t), "-", "")
	if _, err := db.DB.ExecContext(ctx, "create role "+role+" nologin"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := db.DB.ExecContext(cleanup, "reset role"); err != nil {
			t.Error("fixture role was not reset", err)
			return
		}
		if _, err := db.DB.ExecContext(cleanup, "drop owned by "+role); err != nil {
			t.Error("fixture privileges were not removed", err)
			return
		}
		if _, err := db.DB.ExecContext(cleanup, "drop role "+role); err != nil {
			t.Error("fixture role was not removed", err)
		}
	})
	for _, statement := range []string{
		"grant usage on schema public to " + role,
		"grant select,delete on audit_log to " + role,
		"grant insert(ts,org_id,actor_type,actor_id,device_id,runtime_id,session_id,action,result,metadata) on audit_log to " + role,
		"grant update(id) on audit_log to " + role,
		"grant usage,select on sequence audit_log_id_seq to " + role,
		"grant select,insert on audit_archive_batches,audit_log_archive to " + role,
		"grant select,update(slot) on remote_recovery_state to " + role,
	} {
		if _, err := db.DB.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	db.DB.SetMaxOpenConns(1)
	if _, err := db.DB.ExecContext(ctx, "set role "+role); err != nil {
		t.Fatal(err)
	}
	result, err := db.ArchiveAuditHistory(ctx, auditArchiveFixtureRequest(t))
	if err != nil || result.Entries != 1 {
		t.Fatal("limited role could not archive", err)
	}
	if _, err := db.DB.ExecContext(ctx, `update audit_log set id=id`); err == nil {
		t.Fatal("row lock privilege allowed audit mutation")
	}
	if _, err := db.DB.ExecContext(ctx, `update remote_recovery_state set epoch='ffffffff-ffff-4fff-8fff-ffffffffffff'`); err == nil {
		t.Fatal("archive role changed the database epoch")
	}
	if _, err := db.DB.ExecContext(ctx, `insert into audit_log(id,actor_type,actor_id,action,result) overriding system value
	 values($1,'system','fixture','fixture.reused','success')`, id); err == nil {
		t.Fatal("archive role supplied an archived audit identity")
	}
	var history int
	if err := db.DB.QueryRowContext(ctx, `select count(*) from audit_log_archive where source_id=$1`, id).Scan(&history); err != nil || history != 1 {
		t.Fatal("limited role did not preserve history", history, err)
	}
}
