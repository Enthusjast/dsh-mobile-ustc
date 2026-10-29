package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/approval"
	"dsh-mobile-ustc/services/remote/internal/testsupport"
	"github.com/jackc/pgx/v5"
)

func evidenceVerifyFixture(t *testing.T) (*approvalFixture, string) {
	t.Helper()
	f := newApprovalFixture(t)
	f.register(t, f.request)
	compact := f.signed(t, f.request, "reject")
	if _, err := f.control.Decide(f.ctx, f.principal, f.ticket, approvalRaw(t, f.request), compact); err != nil {
		t.Fatal(err)
	}
	return f, compact
}

func TestApprovalEvidenceVerificationAuditsAndDoesNotExposeSignature(t *testing.T) {
	f, compact := evidenceVerifyFixture(t)
	for range 2 {
		result, err := f.database.VerifyApprovalEvidence(f.ctx, f.request.ApprovalID, OriginalDatabaseEpoch)
		if err != nil || result.ApprovalID != f.request.ApprovalID || result.Decision != "reject" || result.SourceEpoch != OriginalDatabaseEpoch || result.Verification != "signature_and_record" || result.FingerprintSource != "captured" {
			t.Fatal("captured evidence failed verification", err)
		}
		raw, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		for _, private := range []string{compact, f.ticket.UserID, f.ticket.DeviceID, "private-tool-argument"} {
			if strings.Contains(string(raw), private) {
				t.Fatal("verification summary exposed private evidence")
			}
		}
	}
	var audits, leaked int
	if err := f.database.DB.QueryRowContext(f.ctx, `select count(*) filter(where action='approval.evidence.verify' and result='success'),
	 count(*) filter(where action='approval.evidence.verify' and (metadata::text like '%private-tool-argument%' or metadata::text like '%decision_jws%')) from audit_log`).Scan(&audits, &leaked); err != nil || audits != 2 || leaked != 0 {
		t.Fatal("successful reads were not safely audited", audits, leaked, err)
	}
}

func evidenceFixtureDSN(t *testing.T, f *approvalFixture) string {
	t.Helper()
	config, err := pgx.ParseConfig(os.Getenv("REMOTE_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal("invalid disposable database configuration")
	}
	var database string
	if err := f.database.DB.QueryRowContext(f.ctx, `select current_database()`).Scan(&database); err != nil {
		t.Fatal(err)
	}
	quote := func(value string) string {
		return "'" + strings.ReplaceAll(strings.ReplaceAll(value, `\`, `\\`), `'`, `\'`) + "'"
	}
	return "host=" + quote(config.Host) + " port=" + strconv.Itoa(int(config.Port)) + " user=" + quote(config.User) + " password=" + quote(config.Password) + " dbname=" + quote(database) + " sslmode=disable"
}

func TestApprovalEvidenceProductionBinaryVerifiesWithoutExposingMaterial(t *testing.T) {
	binary := os.Getenv("REMOTE_TEST_SERVICE_BIN")
	if binary == "" {
		t.Skip("explicit disposable production service binary required")
	}
	f, compact := evidenceVerifyFixture(t)
	dsn := evidenceFixtureDSN(t, f)
	command := exec.CommandContext(f.ctx, binary, "archive", "verify-approval", "--approval-id", f.request.ApprovalID, "--expected-epoch", OriginalDatabaseEpoch)
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "REMOTE_DATABASE_URL=" + dsn, "REMOTE_DATABASE_EPOCH=" + OriginalDatabaseEpoch}
	raw, err := command.CombinedOutput()
	if err != nil {
		t.Fatal("production verification failed", err)
	}
	var result ApprovalEvidenceResult
	if json.Unmarshal(raw, &result) != nil || result.ApprovalID != f.request.ApprovalID || result.Verification != "signature_and_record" || result.FingerprintSource != "captured" {
		t.Fatal("production verifier returned an invalid result")
	}
	for _, private := range []string{compact, f.ticket.UserID, f.ticket.DeviceID, "private-tool-argument", dsn} {
		if strings.Contains(string(raw), private) {
			t.Fatal("production verifier exposed private data")
		}
	}
	var audits int
	if err := f.database.DB.QueryRowContext(f.ctx, `select count(*) from audit_log where action='approval.evidence.verify' and result='success'`).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("production verifier did not audit its read", audits, err)
	}
}

func TestApprovalEvidenceVerificationRejectsDifferentValidSignatureBytes(t *testing.T) {
	f, compact := evidenceVerifyFixture(t)
	alternate := equivalentApprovalSignature(t, compact)
	if alternate == compact {
		t.Fatal("fixture did not produce different signature bytes")
	}
	public, err := integrationP256JWK(f.key)
	if err != nil {
		t.Fatal(err)
	}
	registered := approval.RegisteredKey{UserID: f.ticket.UserID, DeviceID: f.ticket.DeviceID, KeyVersion: f.ticket.DeviceKeyVersion, ApprovalKeyJKT: approvalFixtureKeyJKT(t, f), PublicJWK: public, Active: true}
	if _, err := approval.VerifyDecision(alternate, registered, approvalRaw(t, f.request), time.Now()); err != nil {
		t.Fatal("fixture alternative was not a valid signature", err)
	}
	tx, err := f.database.DB.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(f.ctx, `alter table approval_decision_evidence_material disable trigger approval_decision_evidence_material_guard`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(f.ctx, `update approval_decision_evidence_material set decision_jws=$2 where approval_id=$1`, f.request.ApprovalID, alternate); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(f.ctx, `alter table approval_decision_evidence_material enable trigger approval_decision_evidence_material_guard`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.VerifyApprovalEvidence(f.ctx, f.request.ApprovalID, OriginalDatabaseEpoch); !errors.Is(err, ErrApprovalEvidenceInvalid) {
		t.Fatal("different valid signature replaced the captured bytes", err)
	}
}

func TestApprovalEvidenceVerificationRejectsCorruptionAndAuditsFailure(t *testing.T) {
	f, _ := evidenceVerifyFixture(t)
	tx, err := f.database.DB.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(f.ctx, `alter table approval_decision_evidence_material disable trigger approval_decision_evidence_material_guard`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(f.ctx, `update approval_decision_evidence_material set decision_jws=decision_jws||'x' where approval_id=$1`, f.request.ApprovalID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(f.ctx, `alter table approval_decision_evidence_material enable trigger approval_decision_evidence_material_guard`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.VerifyApprovalEvidence(f.ctx, f.request.ApprovalID, OriginalDatabaseEpoch); !errors.Is(err, ErrApprovalEvidenceInvalid) {
		t.Fatal("corrupted proof was accepted", err)
	}
	var failures int
	if err := f.database.DB.QueryRowContext(f.ctx, `select count(*) from audit_log where action='approval.evidence.verify' and result='failure'`).Scan(&failures); err != nil || failures != 1 {
		t.Fatal("invalid evidence access was not audited", failures, err)
	}
}

func TestApprovalEvidenceVerificationRejectsUnrelatedEpochAndAudits(t *testing.T) {
	f, _ := evidenceVerifyFixture(t)
	tx, err := f.database.DB.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(f.ctx, `alter table approval_decision_evidence disable trigger approval_decision_evidence_guard`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(f.ctx, `update approval_decision_evidence set database_epoch=$2 where approval_id=$1`, f.request.ApprovalID, approvalTestUUID(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(f.ctx, `alter table approval_decision_evidence enable trigger approval_decision_evidence_guard`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.VerifyApprovalEvidence(f.ctx, f.request.ApprovalID, OriginalDatabaseEpoch); !errors.Is(err, ErrRecoveryUnavailable) {
		t.Fatal("unrelated evidence epoch was accepted", err)
	}
	var denied int
	if err := f.database.DB.QueryRowContext(f.ctx, `select count(*) from audit_log where action='approval.evidence.verify' and result='lineage_denied'`).Scan(&denied); err != nil || denied != 1 {
		t.Fatal("unrelated evidence access was not audited", denied, err)
	}
}

func TestApprovalEvidenceVerificationFailsClosedWhenAuditUnavailable(t *testing.T) {
	f, _ := evidenceVerifyFixture(t)
	if _, err := f.database.DB.ExecContext(f.ctx, `create function test_fail_evidence_verify() returns trigger language plpgsql as $$
	 begin if new.action='approval.evidence.verify' then raise exception 'fixture failure'; end if; return new; end $$;
	 create trigger test_fail_evidence_verify before insert on audit_log for each row execute function test_fail_evidence_verify()`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.VerifyApprovalEvidence(f.ctx, f.request.ApprovalID, OriginalDatabaseEpoch); !errors.Is(err, ErrDatabaseUnavailable) {
		t.Fatal("verification returned success without audit", err)
	}
	if _, err := f.database.DB.ExecContext(f.ctx, `drop trigger test_fail_evidence_verify on audit_log; drop function test_fail_evidence_verify()`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.VerifyApprovalEvidence(f.ctx, approvalTestUUID(t), OriginalDatabaseEpoch); !errors.Is(err, ErrApprovalEvidenceUnavailable) {
		t.Fatal("unknown evidence was accepted", err)
	}
	var unavailable, success int
	if err := f.database.DB.QueryRowContext(f.ctx, `select count(*) filter(where action='approval.evidence.verify' and result='unavailable'),
	 count(*) filter(where action='approval.evidence.verify' and result='success') from audit_log`).Scan(&unavailable, &success); err != nil || unavailable != 1 || success != 0 {
		t.Fatal("failed or unavailable access had incorrect audit", unavailable, success, err)
	}
}

func TestApprovalEvidenceFingerprintBackfillsOnlyMatchingOriginals(t *testing.T) {
	f := newApprovalFixture(t)
	applyEvidenceExportFixtureMigration(t, f.ctx, f.database, "down")
	down, err := os.ReadFile("../../../../deploy/sql/027_approval_evidence_fingerprints.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, err := os.ReadFile("../../../../deploy/sql/027_approval_evidence_fingerprints.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.DB.ExecContext(f.ctx, string(down)); err != nil {
		t.Fatal(err)
	}
	first, second := f.request, f.freshRequest(t)
	for _, request := range []approval.Context{first, second} {
		f.register(t, request)
		compact := f.signed(t, request, "reject")
		if _, err := f.control.Decide(f.ctx, f.principal, f.ticket, approvalRaw(t, request), compact); err != nil {
			t.Fatal(err)
		}
	}
	tx, err := f.database.DB.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(f.ctx, `alter table approval_decision_evidence_material disable trigger approval_decision_evidence_material_guard`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(f.ctx, `update approval_decision_evidence_material set decision_jws=decision_jws||'x' where approval_id=$1`, second.ApprovalID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(f.ctx, `alter table approval_decision_evidence_material enable trigger approval_decision_evidence_material_guard`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.DB.ExecContext(f.ctx, string(up)); err != nil {
		t.Fatal(err)
	}
	applyEvidenceExportFixtureMigration(t, f.ctx, f.database, "up")
	result, err := f.database.VerifyApprovalEvidence(f.ctx, first.ApprovalID, OriginalDatabaseEpoch)
	if err != nil || result.FingerprintSource != "backfilled" {
		t.Fatal("matching prior snapshot was not safely backfilled", err)
	}
	if _, err := f.database.VerifyApprovalEvidence(f.ctx, second.ApprovalID, OriginalDatabaseEpoch); !errors.Is(err, ErrApprovalEvidenceUnavailable) {
		t.Fatal("inconsistent prior snapshot received an invented anchor", err)
	}
	var count int
	if err := f.database.DB.QueryRowContext(f.ctx, `select count(*) from approval_evidence_fingerprints`).Scan(&count); err != nil || count != 1 {
		t.Fatal("fingerprint migration backfilled an inconsistent record", count, err)
	}
}

func TestApprovalEvidenceFingerprintMigrationWaitsForInflightDecision(t *testing.T) {
	f := newApprovalFixture(t)
	applyEvidenceExportFixtureMigration(t, f.ctx, f.database, "down")
	down, err := os.ReadFile("../../../../deploy/sql/027_approval_evidence_fingerprints.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, err := os.ReadFile("../../../../deploy/sql/027_approval_evidence_fingerprints.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.DB.ExecContext(f.ctx, string(down)); err != nil {
		t.Fatal(err)
	}
	f.register(t, f.request)
	compact, raw := f.signed(t, f.request, "reject"), approvalRaw(t, f.request)
	if _, err := f.database.DB.ExecContext(f.ctx, `create function test_wait_evidence_material() returns trigger language plpgsql as $$
	 begin perform pg_advisory_xact_lock(763203); return new; end $$;
	 create trigger zz_test_wait_evidence_material before insert on approval_decision_evidence_material for each row execute function test_wait_evidence_material()`); err != nil {
		t.Fatal(err)
	}
	holder, err := f.database.DB.Conn(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if _, err := holder.ExecContext(f.ctx, `select pg_advisory_lock(763203)`); err != nil {
		t.Fatal(err)
	}
	defer holder.ExecContext(context.Background(), `select pg_advisory_unlock(763203)`)
	decision := make(chan error, 1)
	go func() {
		_, err := f.control.Decide(f.ctx, f.principal, f.ticket, raw, compact)
		decision <- err
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
				t.Fatal("fixture did not reach the expected migration lock")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	waitForLock("%update approvals set state%")
	migrated := make(chan error, 1)
	go func() {
		_, err := f.database.DB.ExecContext(f.ctx, string(up))
		migrated <- err
	}()
	waitForLock("%lock table approval_decision_evidence_material%")
	if _, err := holder.ExecContext(f.ctx, `select pg_advisory_unlock(763203)`); err != nil {
		t.Fatal(err)
	}
	if err := <-decision; err != nil {
		t.Fatal("in-flight decision did not commit", err)
	}
	if err := <-migrated; err != nil {
		t.Fatal("fingerprint migration did not complete", err)
	}
	applyEvidenceExportFixtureMigration(t, f.ctx, f.database, "up")
	result, err := f.database.VerifyApprovalEvidence(f.ctx, f.request.ApprovalID, OriginalDatabaseEpoch)
	if err != nil || result.FingerprintSource != "backfilled" {
		t.Fatal("migration missed an in-flight decision", err)
	}
}

func TestApprovalEvidenceVerificationAfterActualRestoreKeepsOldDecisionInert(t *testing.T) {
	f, _ := evidenceVerifyFixture(t)
	ctx, database, _ := testsupport.RestoredPostgresDatabase(t, f.database.DB)
	restored := &Postgres{DB: database}
	epoch, operation := approvalTestUUID(t), approvalTestUUID(t)
	if _, err := restored.QuarantineRecovery(ctx, operation, OriginalDatabaseEpoch, epoch); err != nil {
		t.Fatal(err)
	}
	if _, err := restored.VerifyApprovalEvidence(ctx, f.request.ApprovalID, epoch); !errors.Is(err, ErrRecoveryUnavailable) {
		t.Fatal("evidence was read during quarantine", err)
	}
	manifest := RecoveryAuthority{Version: 1, Complete: true, RecoveryID: operation, DatabaseEpoch: epoch, Issuer: "https://id.example.edu", CapturedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Minute).UTC(), Users: []RecoveryUser{}}
	if _, err := restored.ReleaseRecovery(ctx, epoch, manifest.Issuer, manifest); err != nil {
		t.Fatal(err)
	}
	result, err := restored.VerifyApprovalEvidence(ctx, f.request.ApprovalID, epoch)
	if err != nil || result.SourceEpoch != OriginalDatabaseEpoch || result.CurrentEpoch != epoch {
		t.Fatal("released recovery could not verify old evidence", err)
	}
	var active, audits int
	if err := database.QueryRowContext(ctx, `select (select count(*) from runtime_grants where revoked_at is null),
	 (select count(*) from audit_log where action='approval.evidence.verify' and result='success' and metadata->>'current_epoch'=$1)`, epoch).Scan(&active, &audits); err != nil || active != 0 || audits != 1 {
		t.Fatal("historical verification revived authority or missed audit", active, audits, err)
	}
}

func TestApprovalEvidenceVerificationSerializesWithExpiredDeletion(t *testing.T) {
	f, _ := evidenceVerifyFixture(t)
	f.database.DB.SetMaxOpenConns(5)
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
	if _, err := f.database.DB.ExecContext(f.ctx, `create function test_wait_verify_audit() returns trigger language plpgsql as $$
	 begin if new.action='approval.evidence.verify' then perform pg_advisory_xact_lock(763204); end if; return new; end $$;
	 create trigger test_wait_verify_audit before insert on audit_log for each row execute function test_wait_verify_audit()`); err != nil {
		t.Fatal(err)
	}
	holder, err := f.database.DB.Conn(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if _, err := holder.ExecContext(f.ctx, `select pg_advisory_lock(763204)`); err != nil {
		t.Fatal(err)
	}
	defer holder.ExecContext(context.Background(), `select pg_advisory_unlock(763204)`)
	verified := make(chan error, 1)
	go func() {
		_, err := f.database.VerifyApprovalEvidence(f.ctx, f.request.ApprovalID, OriginalDatabaseEpoch)
		verified <- err
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
				t.Fatal("fixture did not reach the expected verification lock")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	waitForLock("insert into audit_log%")
	deleted := make(chan error, 1)
	go func() {
		_, err := f.database.DB.ExecContext(f.ctx, `delete from approval_decision_evidence_material where approval_id=$1 /* evidence-expiry-race */`, f.request.ApprovalID)
		deleted <- err
	}()
	waitForLock("delete from approval_decision_evidence_material%evidence-expiry-race%")
	if _, err := holder.ExecContext(f.ctx, `select pg_advisory_unlock(763204)`); err != nil {
		t.Fatal(err)
	}
	if err := <-verified; err != nil {
		t.Fatal("verified read did not commit before deletion", err)
	}
	if err := <-deleted; err != nil {
		t.Fatal("expired deletion did not proceed after verification", err)
	}
	if _, err := f.database.VerifyApprovalEvidence(f.ctx, f.request.ApprovalID, OriginalDatabaseEpoch); !errors.Is(err, ErrApprovalEvidenceUnavailable) {
		t.Fatal("deleted material was still reported as available", err)
	}
}

func TestApprovalEvidenceVerificationUsesLimitedRole(t *testing.T) {
	f, _ := evidenceVerifyFixture(t)
	role := "dsh_evidence_reader_" + strings.ReplaceAll(approvalTestUUID(t), "-", "")
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
		"grant insert(actor_type,actor_id,action,result,metadata) on audit_log to " + role,
		"grant select(ts) on audit_log to " + role,
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
	if _, err := f.database.VerifyApprovalEvidence(f.ctx, f.request.ApprovalID, OriginalDatabaseEpoch); err != nil {
		t.Fatal("limited evidence reader could not verify", err)
	}
	if _, err := f.database.DB.ExecContext(f.ctx, `update approval_decision_evidence_material set approval_id=approval_id`); err == nil {
		t.Fatal("row-lock privilege allowed evidence mutation")
	}
	if _, err := f.database.DB.ExecContext(f.ctx, `update remote_recovery_state set epoch='ffffffff-ffff-4fff-8fff-ffffffffffff'`); err == nil {
		t.Fatal("reader changed recovery epoch")
	}
}

func TestApprovalEvidenceVerifierPreventsOlderAuditSchemaRollback(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	applyAuditColdExportFixtureMigration(t, ctx, db, "down")
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
		t.Fatal("audit provenance was removed under the verifier")
	}
	if _, err := conn.ExecContext(ctx, `rollback`); err != nil {
		t.Fatal(err)
	}
	var exists bool
	if err := conn.QueryRowContext(ctx, `select exists(select 1 from information_schema.columns where table_name='audit_log' and column_name='database_epoch')`).Scan(&exists); err != nil || !exists {
		t.Fatal("failed rollback removed audit provenance", err)
	}
}
