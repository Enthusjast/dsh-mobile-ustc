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
	"dsh-mobile-ustc/services/remote/internal/evidencearchive"
	"dsh-mobile-ustc/services/remote/internal/testsupport"
)

func applyEvidenceExportFixtureMigration(t *testing.T, ctx context.Context, db *Postgres, direction string) {
	t.Helper()
	if direction != "up" && direction != "down" {
		t.Fatal("invalid fixture migration direction")
	}
	raw, err := os.ReadFile("../../../../deploy/sql/028_approval_evidence_exports." + direction + ".sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, string(raw)); err != nil {
		t.Fatal("evidence export fixture migration failed", err)
	}
}

func evidenceExportFixture(t *testing.T) (*approvalFixture, EvidenceExportRequest, string) {
	t.Helper()
	f, compact := evidenceVerifyFixture(t)
	key := exportFixtureKey(t, 42)
	request := EvidenceExportRequest{ExportID: approvalTestUUID(t), DomainID: approvalTestUUID(t), DatabaseEpoch: OriginalDatabaseEpoch,
		ApprovalID: f.request.ApprovalID, DestinationFingerprint: strings.Repeat("a", 64), Key: key}
	return f, request, compact
}

func expireEvidenceFixture(t *testing.T, f *approvalFixture) {
	t.Helper()
	tx, err := f.database.DB.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(f.ctx, `alter table approval_decision_evidence disable trigger approval_decision_evidence_guard`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(f.ctx, `update approval_decision_evidence set decided_at=clock_timestamp()-interval '2 years',retain_until=clock_timestamp()-interval '1 year' where approval_id=$1`, f.request.ApprovalID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(f.ctx, `alter table approval_decision_evidence enable trigger approval_decision_evidence_guard`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestEvidenceExportPreparesRebuildsAndPublishesOneIdentity(t *testing.T) {
	f, request, compact := evidenceExportFixture(t)
	state, artifact, err := f.database.PrepareEvidenceExport(f.ctx, request)
	if err != nil || state.State != "prepared" || len(artifact) == 0 {
		t.Fatal("evidence export preparation failed", err)
	}
	opened, err := evidencearchive.Open(request.Key, artifact, request.DomainID, request.ExportID)
	if err != nil || opened.Proof.ApprovalID != request.ApprovalID || opened.Proof.DecisionJWS != compact || bytes.Contains(artifact, []byte(compact)) {
		t.Fatal("encrypted export lost its source proof or exposed plaintext", err)
	}
	retry, none, err := f.database.PrepareEvidenceExport(f.ctx, request)
	if err != nil || len(none) != 0 || retry.ArtifactSHA256 != state.ArtifactSHA256 || !retry.PreparedAt.Equal(state.PreparedAt) {
		t.Fatal("preparation retry changed export identity", err)
	}
	rebuilt, again, err := f.database.RebuildEvidenceExport(f.ctx, request)
	if err != nil || !bytes.Equal(artifact, again) || rebuilt.PayloadSHA256 != state.PayloadSHA256 {
		t.Fatal("prepared export was not reproducible", err)
	}
	changed := request
	changed.Key = exportFixtureKey(t, 43)
	if _, _, err := f.database.PrepareEvidenceExport(f.ctx, changed); !errors.Is(err, ErrEvidenceExportConflict) {
		t.Fatal("export key was rebound", err)
	}
	changed = request
	changed.DomainID = approvalTestUUID(t)
	if _, _, err := f.database.PrepareEvidenceExport(f.ctx, changed); !errors.Is(err, ErrEvidenceExportConflict) {
		t.Fatal("export domain was rebound", err)
	}
	changed = request
	changed.DestinationFingerprint = strings.Repeat("b", 64)
	if _, _, err := f.database.PrepareEvidenceExport(f.ctx, changed); !errors.Is(err, ErrEvidenceExportConflict) {
		t.Fatal("export directory was rebound", err)
	}
	if _, err := f.database.FinishEvidenceExport(f.ctx, request, strings.Repeat("b", 64), len(artifact)); !errors.Is(err, ErrEvidenceExportConflict) {
		t.Fatal("wrong ciphertext digest was published", err)
	}
	state, err = f.database.FinishEvidenceExport(f.ctx, request, coldarchive.Digest(artifact), len(artifact))
	if err != nil || state.State != "published" {
		t.Fatal("publication failed", err)
	}
	if _, err := f.database.AbortEvidenceExport(f.ctx, request); !errors.Is(err, ErrEvidenceExportConflict) {
		t.Fatal("published evidence export was aborted", err)
	}
	var prepared, published int
	if err := f.database.DB.QueryRowContext(f.ctx, `select count(*) filter(where action='approval.evidence.export.prepared'),
	 count(*) filter(where action='approval.evidence.export.published') from audit_log`).Scan(&prepared, &published); err != nil || prepared != 1 || published != 1 {
		t.Fatal("export duplicated its durable audits", prepared, published, err)
	}
	down, err := os.ReadFile("../../../../deploy/sql/028_approval_evidence_exports.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := f.database.DB.Conn(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(f.ctx, string(down)); err == nil {
		t.Fatal("rollback erased export identity")
	}
	if _, err := conn.ExecContext(f.ctx, `rollback`); err != nil {
		t.Fatal(err)
	}
}

func TestEvidenceExportPinsExpiredMaterialUntilAuditedAbort(t *testing.T) {
	f, request, _ := evidenceExportFixture(t)
	expireEvidenceFixture(t, f)
	if _, _, err := f.database.PrepareEvidenceExport(f.ctx, request); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.DB.ExecContext(f.ctx, `delete from approval_decision_evidence_material where approval_id=$1`, request.ApprovalID); err == nil {
		t.Fatal("pending export failed to pin evidence material")
	}
	wrong := request
	wrong.Key = exportFixtureKey(t, 44)
	if _, err := f.database.AbortEvidenceExport(f.ctx, wrong); !errors.Is(err, ErrEvidenceExportConflict) {
		t.Fatal("wrong key aborted evidence protection", err)
	}
	state, err := f.database.AbortEvidenceExport(f.ctx, request)
	if err != nil || state.State != "aborted" {
		t.Fatal("evidence export abort failed", err)
	}
	if _, err := f.database.AbortEvidenceExport(f.ctx, request); err != nil {
		t.Fatal("abort retry failed", err)
	}
	if _, _, err := f.database.RebuildEvidenceExport(f.ctx, request); !errors.Is(err, ErrEvidenceExportConflict) {
		t.Fatal("aborted export was rebuilt", err)
	}
	if _, err := f.database.DB.ExecContext(f.ctx, `delete from approval_decision_evidence_material where approval_id=$1`, request.ApprovalID); err != nil {
		t.Fatal("audited abort did not release expired material", err)
	}
	var audits int
	if err := f.database.DB.QueryRowContext(f.ctx, `select count(*) from audit_log where action='approval.evidence.export.aborted'`).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("abort audit was missing or duplicated", audits, err)
	}
}

func TestEvidenceExportPinsAgainstConcurrentExpiredDeletion(t *testing.T) {
	f, request, _ := evidenceExportFixture(t)
	f.database.DB.SetMaxOpenConns(5)
	expireEvidenceFixture(t, f)
	if _, err := f.database.DB.ExecContext(f.ctx, `create function test_wait_evidence_export() returns trigger language plpgsql as $$
	 begin perform pg_advisory_xact_lock(763205); return new; end $$;
	 create trigger test_wait_evidence_export before insert on approval_evidence_exports for each row execute function test_wait_evidence_export()`); err != nil {
		t.Fatal(err)
	}
	holder, err := f.database.DB.Conn(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if _, err := holder.ExecContext(f.ctx, `select pg_advisory_lock(763205)`); err != nil {
		t.Fatal(err)
	}
	defer holder.ExecContext(context.Background(), `select pg_advisory_unlock(763205)`)
	prepared := make(chan error, 1)
	go func() {
		_, artifact, err := f.database.PrepareEvidenceExport(f.ctx, request)
		clear(artifact)
		prepared <- err
	}()
	waitForLock := func(pattern string) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for {
			var waiting bool
			if err := f.database.DB.QueryRowContext(f.ctx, `select exists(select 1 from pg_stat_activity where datname=current_database() and wait_event_type='Lock' and query like $1)`, pattern).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if waiting {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("fixture did not reach the expected export lock")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	waitForLock("insert into approval_evidence_exports%")
	deleted := make(chan error, 1)
	go func() {
		_, err := f.database.DB.ExecContext(f.ctx, `delete from approval_decision_evidence_material where approval_id=$1 /* evidence-export-expiry */`, request.ApprovalID)
		deleted <- err
	}()
	waitForLock("delete from approval_decision_evidence_material%evidence-export-expiry%")
	if _, err := holder.ExecContext(f.ctx, `select pg_advisory_unlock(763205)`); err != nil {
		t.Fatal(err)
	}
	if err := <-prepared; err != nil {
		t.Fatal("preparation did not commit", err)
	}
	if err := <-deleted; err == nil {
		t.Fatal("concurrent expiry removed newly pinned evidence")
	}
	if _, err := f.database.AbortEvidenceExport(f.ctx, request); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.DB.ExecContext(f.ctx, `delete from approval_decision_evidence_material where approval_id=$1`, request.ApprovalID); err != nil {
		t.Fatal("audited abort did not release expired evidence", err)
	}
}

func TestEvidenceExportRejectsChangedSourceBeforeReusingMaterial(t *testing.T) {
	f, request, _ := evidenceExportFixture(t)
	if _, _, err := f.database.PrepareEvidenceExport(f.ctx, request); err != nil {
		t.Fatal(err)
	}
	tx, err := f.database.DB.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(f.ctx, `alter table approval_decision_evidence disable trigger approval_decision_evidence_guard`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(f.ctx, `update approval_decision_evidence set retain_until=retain_until+interval '1 day' where approval_id=$1`, request.ApprovalID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(f.ctx, `alter table approval_decision_evidence enable trigger approval_decision_evidence_guard`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, artifact, err := f.database.RebuildEvidenceExport(f.ctx, request); !errors.Is(err, ErrEvidenceExportConflict) || len(artifact) != 0 {
		t.Fatal("changed source reused its encryption material", err)
	}
	var denied int
	if err := f.database.DB.QueryRowContext(f.ctx, `select count(*) from audit_log where action='approval.evidence.export.prepare' and result='conflict'`).Scan(&denied); err != nil || denied != 1 {
		t.Fatal("changed source access was not audited", denied, err)
	}
}

func TestEvidenceExportRejectsInvalidSourceAndAuditsFailure(t *testing.T) {
	f, request, compact := evidenceExportFixture(t)
	alternate := equivalentApprovalSignature(t, compact)
	tx, err := f.database.DB.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(f.ctx, `alter table approval_decision_evidence_material disable trigger approval_decision_evidence_material_guard`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(f.ctx, `update approval_decision_evidence_material set decision_jws=$2 where approval_id=$1`, request.ApprovalID, alternate); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(f.ctx, `alter table approval_decision_evidence_material enable trigger approval_decision_evidence_material_guard`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, artifact, err := f.database.PrepareEvidenceExport(f.ctx, request); !errors.Is(err, ErrApprovalEvidenceInvalid) || len(artifact) != 0 {
		t.Fatal("different valid signature was exported", err)
	}
	var failures, exports int
	if err := f.database.DB.QueryRowContext(f.ctx, `select (select count(*) from audit_log where action='approval.evidence.export.prepare' and result='failure'),
	 (select count(*) from approval_evidence_exports)`).Scan(&failures, &exports); err != nil || failures != 1 || exports != 0 {
		t.Fatal("invalid source access was not audited safely", failures, exports, err)
	}
}

func TestEvidenceExportDeferredAuditFailureLeavesNoPinOrArtifact(t *testing.T) {
	f, request, _ := evidenceExportFixture(t)
	if _, err := f.database.DB.ExecContext(f.ctx, `create function test_fail_evidence_export_commit() returns trigger language plpgsql as $$
	 begin if new.action='approval.evidence.export.prepared' then raise exception 'fixture failure'; end if; return null; end $$;
	 create constraint trigger test_fail_evidence_export_commit after insert on audit_log deferrable initially deferred
	 for each row execute function test_fail_evidence_export_commit()`); err != nil {
		t.Fatal(err)
	}
	if _, artifact, err := f.database.PrepareEvidenceExport(f.ctx, request); !errors.Is(err, ErrDatabaseUnavailable) || len(artifact) != 0 {
		t.Fatal("deferred audit failure produced an export", err)
	}
	var exports, audits int
	if err := f.database.DB.QueryRowContext(f.ctx, `select (select count(*) from approval_evidence_exports),
	 (select count(*) from audit_log where action='approval.evidence.export.prepared')`).Scan(&exports, &audits); err != nil || exports != 0 || audits != 0 {
		t.Fatal("failed commit left an export or audit", exports, audits, err)
	}
	if _, err := f.database.DB.ExecContext(f.ctx, `drop trigger test_fail_evidence_export_commit on audit_log; drop function test_fail_evidence_export_commit()`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.database.PrepareEvidenceExport(f.ctx, request); err != nil {
		t.Fatal("failed operation could not be retried", err)
	}
}

func TestEvidenceExportConcurrentPreparationSharesOneArtifact(t *testing.T) {
	f, request, _ := evidenceExportFixture(t)
	type outcome struct {
		state    EvidenceExportState
		artifact []byte
		err      error
	}
	results := make(chan outcome, 4)
	var group sync.WaitGroup
	for range 4 {
		group.Go(func() {
			state, artifact, err := f.database.PrepareEvidenceExport(f.ctx, request)
			results <- outcome{state, artifact, err}
		})
	}
	group.Wait()
	close(results)
	created := 0
	var first EvidenceExportState
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
			t.Fatal("concurrent preparations minted different identities")
		}
	}
	if created != 1 {
		t.Fatal("concurrent preparation created multiple artifacts", created)
	}
}

func TestEvidenceExportPendingStateSurvivesActualRecovery(t *testing.T) {
	f, request, _ := evidenceExportFixture(t)
	expireEvidenceFixture(t, f)
	if _, _, err := f.database.PrepareEvidenceExport(f.ctx, request); err != nil {
		t.Fatal(err)
	}
	ctx, database, _ := testsupport.RestoredPostgresDatabase(t, f.database.DB)
	restored := &Postgres{DB: database}
	epoch, operation := approvalTestUUID(t), approvalTestUUID(t)
	if _, err := restored.QuarantineRecovery(ctx, operation, OriginalDatabaseEpoch, epoch); err != nil {
		t.Fatal(err)
	}
	manifest := RecoveryAuthority{Version: 1, Complete: true, RecoveryID: operation, DatabaseEpoch: epoch, Issuer: "https://id.example.edu", CapturedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Minute).UTC(), Users: []RecoveryUser{}}
	if _, err := restored.ReleaseRecovery(ctx, epoch, manifest.Issuer, manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `delete from approval_decision_evidence_material where approval_id=$1`, request.ApprovalID); err == nil {
		t.Fatal("recovery lost pending evidence protection")
	}
	request.DatabaseEpoch = epoch
	if _, _, err := restored.RebuildEvidenceExport(ctx, request); !errors.Is(err, ErrEvidenceExportConflict) {
		t.Fatal("old export was rebound after recovery", err)
	}
	state, err := restored.AbortEvidenceExport(ctx, request)
	if err != nil || state.State != "aborted" {
		t.Fatal("released recovery could not abort old pending export", err)
	}
	if _, err := database.ExecContext(ctx, `delete from approval_decision_evidence_material where approval_id=$1`, request.ApprovalID); err != nil {
		t.Fatal("recovered abort did not release evidence", err)
	}
}

func TestEvidenceExportAfterActualRestoreVerifiesOldAndNewLineage(t *testing.T) {
	f, request, _ := evidenceExportFixture(t)
	_, artifact, err := f.database.PrepareEvidenceExport(f.ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.FinishEvidenceExport(f.ctx, request, coldarchive.Digest(artifact), len(artifact)); err != nil {
		t.Fatal(err)
	}
	ctx, database, _ := testsupport.RestoredPostgresDatabase(t, f.database.DB)
	restored := &Postgres{DB: database}
	epoch, operation := approvalTestUUID(t), approvalTestUUID(t)
	if _, err := restored.QuarantineRecovery(ctx, operation, OriginalDatabaseEpoch, epoch); err != nil {
		t.Fatal(err)
	}
	manifest := RecoveryAuthority{Version: 1, Complete: true, RecoveryID: operation, DatabaseEpoch: epoch, Issuer: "https://id.example.edu", CapturedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Minute).UTC(), Users: []RecoveryUser{}}
	if _, err := restored.ReleaseRecovery(ctx, epoch, manifest.Issuer, manifest); err != nil {
		t.Fatal(err)
	}
	request.DatabaseEpoch = epoch
	request.DestinationFingerprint = strings.Repeat("b", 64)
	state, err := restored.EvidenceExportForVerification(ctx, request)
	if err != nil || state.State != "published" || state.OperationEpoch != OriginalDatabaseEpoch {
		t.Fatal("old published artifact was not verifiable in a released successor", err)
	}
	if _, err := evidencearchive.Open(request.Key, artifact, request.DomainID, request.ExportID); err != nil {
		t.Fatal("old artifact failed authentication", err)
	}
	if err := restored.RecordEvidenceExportAccess(ctx, request, coldarchive.Digest(artifact), len(artifact), false); err != nil {
		t.Fatal("recovered verification could not be audited", err)
	}
	if _, _, err := restored.PrepareEvidenceExport(ctx, request); !errors.Is(err, ErrEvidenceExportConflict) {
		t.Fatal("old operation was rebound to a new epoch or directory", err)
	}
	request.ExportID = approvalTestUUID(t)
	_, fresh, err := restored.PrepareEvidenceExport(ctx, request)
	if err != nil {
		t.Fatal("new export of old proof failed", err)
	}
	payload, err := evidencearchive.Open(request.Key, fresh, request.DomainID, request.ExportID)
	if err != nil || payload.Proof.SourceEpoch != OriginalDatabaseEpoch || payload.OperationEpoch != epoch || len(payload.Recoveries) != 1 || payload.Recoveries[0].ID != operation {
		t.Fatal("new evidence export lost released lineage", err)
	}
	var active, audited int
	if err := database.QueryRowContext(ctx, `select (select count(*) from runtime_grants where revoked_at is null),
	 (select count(*) from audit_log where action='approval.evidence.export.verified' and metadata->>'current_epoch'=$1)`, epoch).Scan(&active, &audited); err != nil || active != 0 || audited != 1 {
		t.Fatal("evidence verification revived authority or missed audit", active, audited, err)
	}
}

func TestEvidenceExportLimitedRoleCannotAlterProofOrRecoveryEpoch(t *testing.T) {
	f, request, _ := evidenceExportFixture(t)
	role := "dsh_evidence_export_" + strings.ReplaceAll(approvalTestUUID(t), "-", "")
	if _, err := f.database.DB.ExecContext(f.ctx, "create role "+role+" nologin"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := f.database.DB.ExecContext(ctx, "reset role"); err != nil {
			t.Error(err)
			return
		}
		if _, err := f.database.DB.ExecContext(ctx, "drop owned by "+role); err != nil {
			t.Error(err)
			return
		}
		if _, err := f.database.DB.ExecContext(ctx, "drop role "+role); err != nil {
			t.Error(err)
		}
	})
	for _, statement := range []string{
		"grant usage on schema public to " + role,
		"grant select on approval_decision_evidence,approval_decision_evidence_material,approval_evidence_fingerprints,remote_recovery_state,remote_recovery_runs to " + role,
		"grant update(approval_id) on approval_decision_evidence_material to " + role,
		"grant update(slot) on remote_recovery_state to " + role,
		"grant select,insert on approval_evidence_exports to " + role,
		"grant update(state,completed_at) on approval_evidence_exports to " + role,
		"grant insert(actor_type,actor_id,action,result,metadata) on audit_log to " + role,
		"grant usage,select on sequence audit_log_id_seq to " + role,
	} {
		if _, err := f.database.DB.ExecContext(f.ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	f.database.DB.SetMaxOpenConns(1)
	if _, err := f.database.DB.ExecContext(f.ctx, "set role "+role); err != nil {
		t.Fatal(err)
	}
	_, artifact, err := f.database.PrepareEvidenceExport(f.ctx, request)
	if err != nil {
		t.Fatal("limited role could not prepare evidence export", err)
	}
	if _, err := f.database.FinishEvidenceExport(f.ctx, request, coldarchive.Digest(artifact), len(artifact)); err != nil {
		t.Fatal("limited role could not publish evidence export", err)
	}
	if _, err := f.database.DB.ExecContext(f.ctx, `update approval_decision_evidence_material set approval_id=approval_id`); err == nil {
		t.Fatal("material row-lock privilege allowed mutation")
	}
	if _, err := f.database.DB.ExecContext(f.ctx, `update approval_evidence_exports set salt=decode(repeat('00',32),'hex')`); err == nil {
		t.Fatal("publisher changed export encryption identity")
	}
	if _, err := f.database.DB.ExecContext(f.ctx, `update remote_recovery_state set epoch='ffffffff-ffff-4fff-8fff-ffffffffffff'`); err == nil {
		t.Fatal("publisher changed recovery epoch")
	}
}
