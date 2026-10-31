package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/testsupport"
)

func applyEvidenceRetentionFixtureMigration(t *testing.T, ctx context.Context, database *Postgres, direction string) {
	t.Helper()
	if direction != "up" && direction != "down" {
		t.Fatal("invalid retention fixture migration direction")
	}
	raw, err := os.ReadFile("../../../../deploy/sql/045_approval_evidence_retention." + direction + ".sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.DB.ExecContext(ctx, string(raw)); err != nil {
		t.Fatal("evidence retention fixture migration failed", err)
	}
}

func retentionRequest(t *testing.T, f *approvalFixture, years int) ApprovalEvidenceRetentionRequest {
	t.Helper()
	return ApprovalEvidenceRetentionRequest{OperationID: approvalTestUUID(t), ApprovalID: f.request.ApprovalID, DatabaseEpoch: OriginalDatabaseEpoch, RetentionYears: years}
}
func retentionCounts(t *testing.T, f *approvalFixture, operations, audits, materials int) {
	t.Helper()
	var gotOperations, gotAudits, gotMaterials int
	err := f.database.DB.QueryRowContext(f.ctx, `select (select count(*) from approval_evidence_retention_extensions),
        (select count(*) from audit_log where action='approval.evidence.retention.extend'),(select count(*) from approval_decision_evidence_material)`).Scan(&gotOperations, &gotAudits, &gotMaterials)
	if err != nil || gotOperations != operations || gotAudits != audits || gotMaterials != materials {
		t.Fatal("retention records, audit or material mismatch", gotOperations, gotAudits, gotMaterials, err)
	}
}
func TestApprovalEvidenceRetentionExtendsWithoutRewritingProofAndReconcilesOriginalOperation(t *testing.T) {
	f, compact := evidenceVerifyFixture(t)
	snapshot := func() string {
		var value string
		if err := f.database.DB.QueryRowContext(f.ctx, `select jsonb_build_array(to_jsonb(e),to_jsonb(m),to_jsonb(p))::text
            from approval_decision_evidence e join approval_decision_evidence_material m using(approval_id) join approval_evidence_fingerprints p using(approval_id)`).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := snapshot()
	request := retentionRequest(t, f, 2)
	first, err := f.database.ExtendApprovalEvidenceRetention(f.ctx, request)
	if err != nil || first.SourceEpoch != OriginalDatabaseEpoch || first.CurrentEpoch != OriginalDatabaseEpoch || !first.RetainUntil.After(first.PreviousRetainUntil) {
		t.Fatal("retention did not extend", err)
	}
	next := request
	next.OperationID = approvalTestUUID(t)
	next.RetentionYears = 4
	later, err := f.database.ExtendApprovalEvidenceRetention(f.ctx, next)
	if err != nil || !later.PreviousRetainUntil.Equal(first.RetainUntil) || !later.RetainUntil.After(first.RetainUntil) {
		t.Fatal("later retention did not build on previous deadline", err)
	}
	retry, err := f.database.ExtendApprovalEvidenceRetention(f.ctx, request)
	if err != nil || !reflect.DeepEqual(retry, first) {
		t.Fatal("old retry changed its result or extended twice", err)
	}
	for _, change := range []func(*ApprovalEvidenceRetentionRequest){
		func(r *ApprovalEvidenceRetentionRequest) { r.RetentionYears = 3 },
		func(r *ApprovalEvidenceRetentionRequest) { r.ApprovalID = approvalTestUUID(t) },
	} {
		changed := request
		change(&changed)
		if _, err := f.database.ExtendApprovalEvidenceRetention(f.ctx, changed); !errors.Is(err, ErrApprovalRetentionConflict) {
			t.Fatal("operation identity was reused", err)
		}
	}
	shorter := retentionRequest(t, f, 3)
	if _, err := f.database.ExtendApprovalEvidenceRetention(f.ctx, shorter); !errors.Is(err, ErrApprovalRetentionConflict) {
		t.Fatal("new operation shortened retention", err)
	}
	if snapshot() != before {
		t.Fatal("extension rewrote captured evidence or fingerprint")
	}
	if _, err := f.database.VerifyApprovalEvidence(f.ctx, request.ApprovalID, OriginalDatabaseEpoch); err != nil {
		t.Fatal("extension broke historical verification", err)
	}
	retentionCounts(t, f, 2, 2, 1)
	raw, _ := json.Marshal(later)
	for _, private := range []string{compact, f.ticket.UserID, f.ticket.DeviceID, "private-tool-argument"} {
		if strings.Contains(string(raw), private) {
			t.Fatal("retention result exposed evidence")
		}
	}
	for _, statement := range []string{
		`update approval_evidence_retention_extensions set retention_years=9`,
		`delete from approval_evidence_retention_extensions`,
		`truncate approval_evidence_retention_extensions`,
		`delete from approval_decision_evidence_material`,
	} {
		if _, err := f.database.DB.ExecContext(f.ctx, statement); err == nil {
			t.Fatal("retention protection bypassed", statement)
		}
	}
	down, err := os.ReadFile("../../../../deploy/sql/045_approval_evidence_retention.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := f.database.DB.Conn(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(f.ctx, string(down)); err == nil {
		t.Fatal("retention history allowed destructive rollback")
	}
	if _, err := conn.ExecContext(f.ctx, `rollback`); err != nil {
		t.Fatal(err)
	}
	retentionCounts(t, f, 2, 2, 1)
}

func TestApprovalEvidenceRetentionFailuresRollBackAndDoNotReportSuccess(t *testing.T) {
	for _, boundary := range []string{"audit-error", "audit-ignore", "operation-ignore"} {
		t.Run(boundary, func(t *testing.T) {
			f, _ := evidenceVerifyFixture(t)
			request := retentionRequest(t, f, 2)
			table, predicate, body := "audit_log", "new.action='approval.evidence.retention.extend'", "raise exception 'PRIVATE_RETENTION_AUDIT';"
			if boundary == "audit-ignore" {
				body = "return null;"
			}
			if boundary == "operation-ignore" {
				table = "approval_evidence_retention_extensions"
				predicate = "true"
				body = "return null;"
			}
			if _, err := f.database.DB.ExecContext(f.ctx, `create function fixture_retention_failure() returns trigger language plpgsql as $$ begin if `+predicate+` then `+body+` end if; return new; end $$;
                create trigger aaa_retention_failure before insert on `+table+` for each row execute function fixture_retention_failure()`); err != nil {
				t.Fatal(err)
			}
			if _, err := f.database.ExtendApprovalEvidenceRetention(f.ctx, request); !errors.Is(err, ErrDatabaseUnavailable) || strings.Contains(err.Error(), "PRIVATE_") {
				t.Fatal("failed retention reported success or leaked cause", err)
			}
			retentionCounts(t, f, 0, 0, 1)
			if _, err := f.database.DB.ExecContext(f.ctx, `drop trigger aaa_retention_failure on `+table+`; drop function fixture_retention_failure()`); err != nil {
				t.Fatal(err)
			}
			if _, err := f.database.ExtendApprovalEvidenceRetention(f.ctx, request); err != nil {
				t.Fatal("same request could not recover", err)
			}
			retentionCounts(t, f, 1, 1, 1)
		})
	}
}

func retentionAuditBarrier(t *testing.T, f *approvalFixture, action string) func() {
	t.Helper()
	f.database.DB.SetMaxOpenConns(6)
	if _, err := f.database.DB.ExecContext(f.ctx, `create function fixture_retention_wait() returns trigger language plpgsql as $$
        begin if new.action='`+action+`' then perform pg_advisory_xact_lock(845201); end if; return new; end $$;
        create trigger fixture_retention_wait before insert on audit_log for each row execute function fixture_retention_wait()`); err != nil {
		t.Fatal(err)
	}
	holder, err := f.database.DB.Conn(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := holder.ExecContext(f.ctx, `select pg_advisory_lock(845201)`); err != nil {
		holder.Close()
		t.Fatal(err)
	}
	var once sync.Once
	release := func() {
		once.Do(func() {
			_, _ = holder.ExecContext(context.Background(), `select pg_advisory_unlock(845201)`)
			_ = holder.Close()
		})
	}
	t.Cleanup(release)
	return release
}
func TestApprovalEvidenceRetentionSerializesWithExpiredMaterialDeletion(t *testing.T) {
	for _, first := range []string{"extension", "deletion"} {
		t.Run(first, func(t *testing.T) {
			f, _ := evidenceVerifyFixture(t)
			expireEvidenceFixture(t, f)
			action := "approval.evidence.retention.extend"
			if first == "deletion" {
				action = "approval.evidence.material.delete"
			}
			release := retentionAuditBarrier(t, f, action)
			request := retentionRequest(t, f, 3)
			extended, deleted := make(chan error, 1), make(chan error, 1)
			extend := func() { _, err := f.database.ExtendApprovalEvidenceRetention(f.ctx, request); extended <- err }
			remove := func() {
				_, err := f.database.DB.ExecContext(f.ctx, `delete from approval_decision_evidence_material where approval_id=$1 /* retention-delete-race */`, request.ApprovalID)
				deleted <- err
			}
			if first == "extension" {
				go extend()
			} else {
				go remove()
			}
			waitForGrantLock(t, f.ctx, f.database, "")
			if first == "extension" {
				go remove()
				waitForGrantLock(t, f.ctx, f.database, "retention-delete-race")
			} else {
				go extend()
				waitForGrantLock(t, f.ctx, f.database, "select approval_id::text")
			}
			release()
			extendErr, deleteErr := <-extended, <-deleted
			if first == "extension" {
				if extendErr != nil || deleteErr == nil {
					t.Fatal("delete missed committed extension", extendErr, deleteErr)
				}
				retentionCounts(t, f, 1, 1, 1)
			} else {
				if deleteErr != nil || !errors.Is(extendErr, ErrApprovalEvidenceUnavailable) {
					t.Fatal("extension recreated deleted material", extendErr, deleteErr)
				}
				retentionCounts(t, f, 0, 0, 0)
			}
		})
	}
}
func TestApprovalEvidenceRetentionRejectsStaleTransactionSnapshotsAndConcurrentDuplicateWrites(t *testing.T) {
	f, _ := evidenceVerifyFixture(t)
	expireEvidenceFixture(t, f)
	f.database.DB.SetMaxOpenConns(6)
	old, err := f.database.DB.BeginTx(f.ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer old.Rollback()
	var count int
	if err := old.QueryRowContext(f.ctx, `select count(*) from approval_evidence_retention_extensions`).Scan(&count); err != nil || count != 0 {
		t.Fatal(err)
	}
	request := retentionRequest(t, f, 3)
	var group sync.WaitGroup
	results := make(chan ApprovalEvidenceRetentionResult, 4)
	failures := make(chan error, 4)
	for range 4 {
		group.Go(func() {
			value, err := f.database.ExtendApprovalEvidenceRetention(f.ctx, request)
			results <- value
			failures <- err
		})
	}
	group.Wait()
	close(results)
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal("duplicate extension failed", err)
		}
	}
	var first *ApprovalEvidenceRetentionResult
	for value := range results {
		if first == nil {
			first = &value
		} else if !reflect.DeepEqual(*first, value) {
			t.Fatal("concurrent retries returned different receipts")
		}
	}
	if _, err := old.ExecContext(f.ctx, `delete from approval_decision_evidence_material where approval_id=$1`, request.ApprovalID); err == nil {
		t.Fatal("stale snapshot deleted extended evidence")
	}
	if err := old.Rollback(); err != nil {
		t.Fatal(err)
	}
	old, err = f.database.DB.BeginTx(f.ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		t.Fatal(err)
	}
	defer old.Rollback()
	if _, err := old.ExecContext(f.ctx, `insert into approval_evidence_retention_extensions(id,approval_id,operation_epoch,retention_years) values($1,$2,$3,4)`, approvalTestUUID(t), request.ApprovalID, OriginalDatabaseEpoch); err == nil {
		t.Fatal("non-read-committed extension was accepted")
	}
	retentionCounts(t, f, 1, 1, 1)
}

func TestApprovalEvidenceRetentionAfterActualRestorePreservesPinAndRequiresNewEpoch(t *testing.T) {
	f, _ := evidenceVerifyFixture(t)
	expireEvidenceFixture(t, f)
	request := retentionRequest(t, f, 3)
	first, err := f.database.ExtendApprovalEvidenceRetention(f.ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	ctx, restoredDB, _ := testsupport.RestoredPostgresDatabase(t, f.database.DB)
	restored := &Postgres{DB: restoredDB}
	epoch, operation := approvalTestUUID(t), approvalTestUUID(t)
	if _, err := restored.QuarantineRecovery(ctx, operation, OriginalDatabaseEpoch, epoch); err != nil {
		t.Fatal(err)
	}
	next := request
	next.DatabaseEpoch = epoch
	next.OperationID = approvalTestUUID(t)
	next.RetentionYears = 4
	if _, err := restored.ExtendApprovalEvidenceRetention(ctx, next); !errors.Is(err, ErrRecoveryUnavailable) {
		t.Fatal("quarantine allowed extension", err)
	}
	manifest := RecoveryAuthority{Version: 1, Complete: true, RecoveryID: operation, DatabaseEpoch: epoch, Issuer: "https://id.example.edu", CapturedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Minute).UTC(), Users: []RecoveryUser{}}
	if _, err := restored.ReleaseRecovery(ctx, epoch, manifest.Issuer, manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := restored.ExtendApprovalEvidenceRetention(ctx, request); !errors.Is(err, ErrRecoveryUnavailable) {
		t.Fatal("old epoch operation became current", err)
	}
	if _, err := restoredDB.ExecContext(ctx, `delete from approval_decision_evidence_material where approval_id=$1`, request.ApprovalID); err == nil {
		t.Fatal("restore lost existing retention pin")
	}
	result, err := restored.ExtendApprovalEvidenceRetention(ctx, next)
	if err != nil || result.SourceEpoch != OriginalDatabaseEpoch || result.CurrentEpoch != epoch || !result.PreviousRetainUntil.Equal(first.RetainUntil) {
		t.Fatal("released successor could not extend historical retention", err)
	}
	var active int
	if err := restoredDB.QueryRowContext(ctx, `select count(*) from runtime_grants where revoked_at is null`).Scan(&active); err != nil || active != 0 {
		t.Fatal("retention revived authorization", active, err)
	}
}

func TestApprovalEvidenceRetentionProductionBinaryReconcilesLostOutputWithoutPrivateMaterial(t *testing.T) {
	binary := os.Getenv("REMOTE_TEST_SERVICE_BIN")
	if binary == "" {
		t.Skip("explicit disposable service binary required")
	}
	f, compact := evidenceVerifyFixture(t)
	request := retentionRequest(t, f, 3)
	dsn := evidenceFixtureDSN(t, f)
	args := []string{"archive", "retain-approval", "--operation-id", request.OperationID, "--approval-id", request.ApprovalID, "--expected-epoch", OriginalDatabaseEpoch, "--retention-years", "3"}
	process := func() *exec.Cmd {
		command := exec.CommandContext(f.ctx, binary, args...)
		command.Env = []string{"PATH=" + os.Getenv("PATH"), "REMOTE_DATABASE_URL=" + dsn, "REMOTE_DATABASE_EPOCH=" + OriginalDatabaseEpoch}
		return command
	}
	lost := process()
	lost.Stdout = io.Discard
	if err := lost.Run(); err != nil {
		t.Fatal("initial production extension failed", err)
	}
	raw, err := process().CombinedOutput()
	if err != nil {
		t.Fatal("production retry failed", err)
	}
	var result ApprovalEvidenceRetentionResult
	if json.Unmarshal(raw, &result) != nil || result.OperationID != request.OperationID || result.RetentionYears != 3 {
		t.Fatal("production retry lost result")
	}
	for _, private := range []string{dsn, compact, f.ticket.UserID, f.ticket.DeviceID, "private-tool-argument"} {
		if strings.Contains(string(raw), private) {
			t.Fatal("production output exposed private evidence")
		}
	}
	retentionCounts(t, f, 1, 1, 1)
}

func TestApprovalEvidenceRetentionUsesUTCYearsAndRejectsElapsedExtensions(t *testing.T) {
	f, _ := evidenceVerifyFixture(t)
	expireEvidenceFixture(t, f)
	if _, err := f.database.ExtendApprovalEvidenceRetention(f.ctx, retentionRequest(t, f, 2)); !errors.Is(err, ErrApprovalRetentionConflict) {
		t.Fatal("elapsed extension was accepted", err)
	}
	f.database.DB.SetMaxOpenConns(1)
	leap := time.Now().UTC().Year() / 4 * 4
	for time.Date(leap, 2, 29, 0, 0, 0, 0, time.UTC).Month() != time.February {
		leap -= 4
	}
	decided := time.Date(leap, 2, 29, 12, 34, 56, 0, time.UTC)
	tx, err := f.database.DB.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(f.ctx, `alter table approval_decision_evidence disable trigger approval_decision_evidence_guard;
        set local timezone='Pacific/Apia'`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(f.ctx, `update approval_decision_evidence set decided_at=$1,retain_until=(($1::timestamptz at time zone 'UTC')+interval '1 year') at time zone 'UTC'`, decided); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(f.ctx, `alter table approval_decision_evidence enable trigger approval_decision_evidence_guard`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.DB.ExecContext(f.ctx, `set timezone='Pacific/Apia'`); err != nil {
		t.Fatal(err)
	}
	first, err := f.database.ExtendApprovalEvidenceRetention(f.ctx, retentionRequest(t, f, 7))
	if err != nil || !first.RetainUntil.Equal(time.Date(leap+7, 2, 28, 12, 34, 56, 0, time.UTC)) {
		t.Fatal("non-leap UTC year extension changed wall time", err, first.RetainUntil)
	}
	next, err := f.database.ExtendApprovalEvidenceRetention(f.ctx, retentionRequest(t, f, 8))
	if err != nil || !next.RetainUntil.Equal(time.Date(leap+8, 2, 29, 12, 34, 56, 0, time.UTC)) {
		t.Fatal("leap UTC year extension changed wall time", err, next.RetainUntil)
	}
	retentionCounts(t, f, 2, 2, 1)
}

func TestApprovalEvidenceRetentionElapsedPinAllowsOnlyAuditedMaterialDeletion(t *testing.T) {
	f, _ := evidenceVerifyFixture(t)
	expireEvidenceFixture(t, f)
	request := retentionRequest(t, f, 3)
	if _, err := f.database.ExtendApprovalEvidenceRetention(f.ctx, request); err != nil {
		t.Fatal(err)
	}
	// Privileged fixture-only time shift. Ordinary extension updates are denied.
	tx, err := f.database.DB.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, statement := range []string{
		`alter table approval_evidence_retention_extensions disable trigger approval_evidence_retention_guard`,
		`update approval_evidence_retention_extensions set retain_until=retain_until-interval '3 years',previous_retain_until=previous_retain_until-interval '3 years',recorded_at=recorded_at-interval '3 years'`,
		`alter table approval_evidence_retention_extensions enable trigger approval_evidence_retention_guard`,
	} {
		if _, err := tx.ExecContext(f.ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.DB.ExecContext(f.ctx, `delete from approval_decision_evidence_material where approval_id=$1`, request.ApprovalID); err != nil {
		t.Fatal("elapsed extension prevented valid deletion", err)
	}
	retentionCounts(t, f, 1, 1, 0)
	var identities, fingerprints, audits int
	if err := f.database.DB.QueryRowContext(f.ctx, `select (select count(*) from approval_decision_evidence),
        (select count(*) from approval_evidence_fingerprints),(select count(*) from audit_log where action='approval.evidence.material.delete')`).Scan(&identities, &fingerprints, &audits); err != nil || identities != 1 || fingerprints != 1 || audits != 1 {
		t.Fatal("deletion lost evidence identity or audit", err)
	}
	if _, err := f.database.ExtendApprovalEvidenceRetention(f.ctx, retentionRequest(t, f, 4)); !errors.Is(err, ErrApprovalEvidenceUnavailable) {
		t.Fatal("missing material was recreated", err)
	}
}

func TestApprovalEvidenceRetentionRestrictedRoleNeedsExplicitGrantAndCannotMutateMaterial(t *testing.T) {
	f, _ := evidenceVerifyFixture(t)
	f.database.DB.SetMaxOpenConns(1)
	role := "retention_" + strings.ReplaceAll(approvalTestUUID(t), "-", "")
	if _, err := f.database.DB.ExecContext(f.ctx, "create role "+role); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.database.DB.ExecContext(context.Background(), "reset role")
		_, _ = f.database.DB.ExecContext(context.Background(), "drop owned by "+role)
		_, _ = f.database.DB.ExecContext(context.Background(), "drop role "+role)
	})
	for _, statement := range []string{
		"grant usage on schema public to " + role,
		"grant select on remote_recovery_state,remote_recovery_runs,approval_decision_evidence,approval_evidence_retention_extensions to " + role,
		"grant update(slot) on remote_recovery_state to " + role,
		"grant select(approval_id),update(approval_id) on approval_decision_evidence_material to " + role,
		"grant insert(actor_type,actor_id,action,result,metadata),select(id) on audit_log to " + role,
		"grant usage on sequence audit_log_id_seq to " + role,
		"set role " + role,
	} {
		if _, err := f.database.DB.ExecContext(f.ctx, statement); err != nil {
			t.Fatal("role fixture setup", err)
		}
	}
	request := retentionRequest(t, f, 2)
	if _, err := f.database.ExtendApprovalEvidenceRetention(f.ctx, request); !errors.Is(err, ErrDatabaseUnavailable) {
		t.Fatal("read role extended retention without INSERT", err)
	}
	if _, err := f.database.DB.ExecContext(f.ctx, "reset role"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.DB.ExecContext(f.ctx, "grant insert(id,approval_id,operation_epoch,retention_years) on approval_evidence_retention_extensions to "+role); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.DB.ExecContext(f.ctx, "set role "+role); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.ExtendApprovalEvidenceRetention(f.ctx, request); err != nil {
		t.Fatal("least-privilege retention role failed", err)
	}
	for _, statement := range []string{
		`select decision_jws from approval_decision_evidence_material`,
		`update approval_decision_evidence_material set approval_id=approval_id`,
		`delete from approval_decision_evidence_material`,
		`update approval_evidence_retention_extensions set retention_years=9`,
	} {
		if _, err := f.database.DB.ExecContext(f.ctx, statement); err == nil {
			t.Fatal("retention role read or changed protected material", statement)
		}
	}
	if _, err := f.database.DB.ExecContext(f.ctx, "reset role"); err != nil {
		t.Fatal(err)
	}
	retentionCounts(t, f, 1, 1, 1)
}
