package store

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/approval"
	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/testsupport"
)

func TestApprovalEvidenceCapturesVerifiedKeyWithoutToolArguments(t *testing.T) {
	f := newApprovalFixture(t)
	f.register(t, f.request)
	if _, err := f.database.DB.ExecContext(f.ctx, `update devices set approval_public_jwk=jsonb_set(approval_public_jwk,'{kid}','"PRIVATE_DEVICE_LABEL"'::jsonb) where id=$1`, f.ticket.DeviceID); err != nil {
		t.Fatal(err)
	}
	compact := f.signed(t, f.request, "allow_once")
	status, err := f.control.Decide(f.ctx, f.principal, f.ticket, approvalRaw(t, f.request), compact)
	if err != nil || status.State != "decision_received" {
		t.Fatal("decision was not admitted", err)
	}
	if _, err := f.control.Decide(f.ctx, f.principal, f.ticket, approvalRaw(t, f.request), compact); err != nil {
		t.Fatal("decision retry failed", err)
	}
	var savedJWS, keyJKT, binding, savedEpoch string
	var public []byte
	var decided, retained time.Time
	var count int
	if err := f.database.DB.QueryRowContext(f.ctx, `select m.decision_jws,m.public_jwk::text,e.approval_key_jkt,e.binding_sha256,e.decided_at,e.retain_until,e.database_epoch::text,
	 (select count(*) from approval_decision_evidence) from approval_decision_evidence e join approval_decision_evidence_material m using(approval_id) where e.approval_id=$1`, f.request.ApprovalID).
		Scan(&savedJWS, &public, &keyJKT, &binding, &decided, &retained, &savedEpoch, &count); err != nil || savedJWS != compact || binding != status.BindingSHA256 || count != 1 || savedEpoch != OriginalDatabaseEpoch {
		t.Fatal("decision evidence was not captured exactly once", err)
	}
	if retained.Before(decided.UTC().AddDate(1, 0, 0).Add(-24 * time.Hour)) {
		t.Fatal("decision evidence retention is too short")
	}
	// The source arguments exist only in the local fixture. They can be used to
	// independently check the captured key and signature, but are not persisted.
	registered := approval.RegisteredKey{UserID: f.ticket.UserID, DeviceID: f.ticket.DeviceID, KeyVersion: 1, ApprovalKeyJKT: keyJKT, PublicJWK: public, Active: true}
	if _, err := approval.VerifyDecision(savedJWS, registered, approvalRaw(t, f.request), decided); err != nil {
		t.Fatal("captured signature or public key did not verify", err)
	}
	parts := strings.Split(savedJWS, ".")
	if len(parts) != 3 {
		t.Fatal("captured signature was not compact JWS")
	}
	claims, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || bytes.Contains(claims, []byte("private-tool-argument")) || bytes.Contains(public, []byte("private-tool-argument")) || bytes.Contains(public, []byte("PRIVATE_DEVICE_LABEL")) {
		t.Fatal("decision evidence retained tool arguments", err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newJWK, err := integrationP256JWK(other)
	if err != nil {
		t.Fatal(err)
	}
	newJKT, err := auth.PublicP256JWKThumbprintJSON(newJWK)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.DB.ExecContext(f.ctx, `update devices set approval_public_jwk=$1,approval_key_thumbprint=$2,key_version=2,revoked_at=clock_timestamp() where id=$3`, newJWK, newJKT, f.ticket.DeviceID); err != nil {
		t.Fatal(err)
	}
	var after []byte
	if err := f.database.DB.QueryRowContext(f.ctx, `select public_jwk::text from approval_decision_evidence_material where approval_id=$1`, f.request.ApprovalID).Scan(&after); err != nil || !bytes.Equal(public, after) {
		t.Fatal("key replacement changed historical evidence", err)
	}
	if _, err := approval.VerifyDecision(savedJWS, registered, approvalRaw(t, f.request), decided); err != nil {
		t.Fatal("key replacement prevented verification of captured evidence", err)
	}
	for _, statement := range []string{
		`update approval_decision_evidence_material set decision_jws='changed'`,
		`delete from approval_decision_evidence_material`,
		`delete from approval_decision_evidence`,
		`truncate approval_decision_evidence_material`,
		`update approvals set decision_jws='changed' where decision is not null`,
		`update approvals set binding_sha256=repeat('b',64) where decision is not null`,
	} {
		if _, err := f.database.DB.ExecContext(f.ctx, statement); err == nil {
			t.Fatal("captured decision was changed before retention")
		}
	}
}

func TestApprovalEvidenceAndDecisionRollbackTogetherOnFailure(t *testing.T) {
	f := newApprovalFixture(t)
	f.register(t, f.request)
	compact := f.signed(t, f.request, "reject")
	for _, target := range []string{"material", "audit"} {
		var sqlText string
		if target == "material" {
			sqlText = `create function test_fail_evidence() returns trigger language plpgsql as $$ begin raise exception 'fixture failure'; end $$;
			 create trigger test_fail_evidence before insert on approval_decision_evidence_material for each row execute function test_fail_evidence()`
		} else {
			sqlText = `create function test_fail_evidence() returns trigger language plpgsql as $$ begin if new.action='approval.decided' then raise exception 'fixture failure'; end if; return new; end $$;
			 create trigger test_fail_evidence before insert on audit_log for each row execute function test_fail_evidence()`
		}
		if _, err := f.database.DB.ExecContext(f.ctx, sqlText); err != nil {
			t.Fatal(err)
		}
		if _, err := f.control.Decide(f.ctx, f.principal, f.ticket, approvalRaw(t, f.request), compact); !errors.Is(err, ErrDatabaseUnavailable) {
			t.Fatal("decision ignored evidence or audit failure", err)
		}
		assertApprovalPending(t, f, f.request)
		var evidence, materials, decisions int
		if err := f.database.DB.QueryRowContext(f.ctx, `select (select count(*) from approval_decision_evidence),
		 (select count(*) from approval_decision_evidence_material),(select count(*) from audit_log where action='approval.decided')`).Scan(&evidence, &materials, &decisions); err != nil || evidence != 0 || materials != 0 || decisions != 0 {
			t.Fatal("failed decision left partial evidence", evidence, materials, decisions, err)
		}
		table := "approval_decision_evidence_material"
		if target == "audit" {
			table = "audit_log"
		}
		if _, err := f.database.DB.ExecContext(f.ctx, `drop trigger test_fail_evidence on `+table+`; drop function test_fail_evidence()`); err != nil {
			t.Fatal(err)
		}
	}
	if status, err := f.control.Decide(f.ctx, f.principal, f.ticket, approvalRaw(t, f.request), compact); err != nil || status.State != "denied" {
		t.Fatal("valid decision could not be retried", err)
	}
}

func TestApprovalEvidenceDoesNotInventHistoricalKeySnapshots(t *testing.T) {
	f := newApprovalFixture(t)
	down, err := os.ReadFile("../../../../deploy/sql/025_approval_decision_evidence.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, err := os.ReadFile("../../../../deploy/sql/025_approval_decision_evidence.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.DB.ExecContext(f.ctx, string(down)); err != nil {
		t.Fatal(err)
	}
	f.register(t, f.request)
	compact := f.signed(t, f.request, "reject")
	if _, err := f.control.Decide(f.ctx, f.principal, f.ticket, approvalRaw(t, f.request), compact); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.DB.ExecContext(f.ctx, string(up)); err != nil {
		t.Fatal(err)
	}
	var captured sql.NullString
	var count int
	if err := f.database.DB.QueryRowContext(f.ctx, `select decision_evidence_epoch::text,(select count(*) from approval_decision_evidence) from approvals where id=$1`, f.request.ApprovalID).Scan(&captured, &count); err != nil || captured.Valid || count != 0 {
		t.Fatal("migration invented an at-decision key snapshot", err)
	}
	if _, err := f.control.Decide(f.ctx, f.principal, f.ticket, approvalRaw(t, f.request), compact); err != nil {
		t.Fatal("legacy decision retry changed behavior", err)
	}
	if _, err := f.database.DB.ExecContext(f.ctx, `insert into approval_decision_evidence(approval_id,database_epoch,runtime_id,runtime_epoch,session_id,execution_id,user_id,device_id,key_version,approval_key_jkt,decision,binding_sha256,payload_sha256,decided_at,retain_until)
	 select id,$2,runtime_id,runtime_epoch,session_id,execution_id,decided_by,decided_device_id,decision_key_version,decision_approval_key_jkt,decision,binding_sha256,decision_payload_sha256,decided_at,
	 ((decided_at at time zone 'UTC')+interval '1 year') at time zone 'UTC' from approvals where id=$1`, f.request.ApprovalID, OriginalDatabaseEpoch); err == nil {
		t.Fatal("a legacy decision acquired an unverified historical snapshot")
	}
}

func TestApprovalEvidencePreventsOutOfOrderMigrationRollback(t *testing.T) {
	f := newApprovalFixture(t)
	f.register(t, f.request)
	if _, err := f.control.Decide(f.ctx, f.principal, f.ticket, approvalRaw(t, f.request), f.signed(t, f.request, "reject")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"006_approval_control", "007_approval_host_results"} {
		body, err := os.ReadFile("../../../../deploy/sql/" + name + ".down.sql")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.database.DB.ExecContext(f.ctx, string(body)); err == nil {
			t.Fatal("older migration rolled back while evidence depended on it", name)
		}
	}
	down, err := os.ReadFile("../../../../deploy/sql/025_approval_decision_evidence.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := f.database.DB.Conn(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(f.ctx, string(down)); err == nil {
		t.Fatal("evidence migration dropped captured identity")
	}
	if _, err := conn.ExecContext(f.ctx, `rollback`); err != nil {
		t.Fatal(err)
	}
	var evidence int
	if err := conn.QueryRowContext(f.ctx, `select count(*) from approval_decision_evidence_material`).Scan(&evidence); err != nil || evidence != 1 {
		t.Fatal("failed rollback lost evidence", evidence, err)
	}
}

func TestApprovalEvidenceExpiredMaterialDeletionPreservesIdentity(t *testing.T) {
	f := newApprovalFixture(t)
	f.register(t, f.request)
	compact := f.signed(t, f.request, "reject")
	if _, err := f.control.Decide(f.ctx, f.principal, f.ticket, approvalRaw(t, f.request), compact); err != nil {
		t.Fatal(err)
	}
	var key string
	if err := f.database.DB.QueryRowContext(f.ctx, `select public_jwk::text from approval_decision_evidence_material where approval_id=$1`, f.request.ApprovalID).Scan(&key); err != nil {
		t.Fatal(err)
	}
	// Privileged fixture-only time shift; ordinary history updates are denied.
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
	if _, err := f.database.DB.ExecContext(f.ctx, `create function test_fail_evidence_delete_audit() returns trigger language plpgsql as $$
	 begin if new.action='approval.evidence.material.delete' then raise exception 'fixture failure'; end if; return new; end $$;
	 create trigger test_fail_evidence_delete_audit before insert on audit_log for each row execute function test_fail_evidence_delete_audit()`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.DB.ExecContext(f.ctx, `delete from approval_decision_evidence_material where approval_id=$1`, f.request.ApprovalID); err == nil {
		t.Fatal("evidence deletion ignored audit failure")
	}
	var present int
	if err := f.database.DB.QueryRowContext(f.ctx, `select count(*) from approval_decision_evidence_material`).Scan(&present); err != nil || present != 1 {
		t.Fatal("failed audit deleted evidence", present, err)
	}
	if _, err := f.database.DB.ExecContext(f.ctx, `drop trigger test_fail_evidence_delete_audit on audit_log; drop function test_fail_evidence_delete_audit()`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.DB.ExecContext(f.ctx, `delete from approval_decision_evidence_material where approval_id=$1`, f.request.ApprovalID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.DB.ExecContext(f.ctx, `insert into approval_decision_evidence_material(approval_id,decision_jws,public_jwk) values($1,$2,$3::jsonb)`, f.request.ApprovalID, compact, key); err == nil {
		t.Fatal("expired evidence was silently recreated")
	}
	var headers, materials, audits int
	if err := f.database.DB.QueryRowContext(f.ctx, `select (select count(*) from approval_decision_evidence), (select count(*) from approval_decision_evidence_material),
	 (select count(*) from audit_log where action='approval.evidence.material.delete')`).Scan(&headers, &materials, &audits); err != nil || headers != 1 || materials != 0 || audits != 1 {
		t.Fatal("expiry lost its identity or audit", headers, materials, audits, err)
	}
}

func TestApprovalEvidenceSurvivesActualRestoreWithoutRevivingDecision(t *testing.T) {
	f := newApprovalFixture(t)
	f.register(t, f.request)
	compact := f.signed(t, f.request, "allow_once")
	if _, err := f.control.Decide(f.ctx, f.principal, f.ticket, approvalRaw(t, f.request), compact); err != nil {
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
	var state, evidenceEpoch, saved string
	var active int
	if err := database.QueryRowContext(ctx, `select a.state,e.database_epoch::text,m.decision_jws,
	 (select count(*) from runtime_grants where revoked_at is null) from approvals a join approval_decision_evidence e on e.approval_id=a.id
	 join approval_decision_evidence_material m on m.approval_id=e.approval_id where a.id=$1`, f.request.ApprovalID).
		Scan(&state, &evidenceEpoch, &saved, &active); err != nil || state != "outcome_unknown" || evidenceEpoch != OriginalDatabaseEpoch || saved != compact || active != 0 {
		t.Fatal("restore revived a decision or lost its evidence", state, active, err)
	}
}

func TestApprovalEvidenceLocksRecoveryBeforeDeviceDuringDecision(t *testing.T) {
	f := newApprovalFixture(t)
	f.register(t, f.request)
	compact := f.signed(t, f.request, "reject")
	raw := approvalRaw(t, f.request)
	holder, err := f.database.DB.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	if _, err := holder.ExecContext(f.ctx, `set local lock_timeout='1s'`); err != nil {
		t.Fatal(err)
	}
	if _, err := holder.ExecContext(f.ctx, `select epoch from remote_recovery_state where slot=1 for update`); err != nil {
		t.Fatal(err)
	}
	decided := make(chan error, 1)
	go func() {
		_, err := f.control.Decide(f.ctx, f.principal, f.ticket, raw, compact)
		decided <- err
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		var waiting bool
		if err := f.database.DB.QueryRowContext(f.ctx, `select exists(select 1 from pg_stat_activity where datname=current_database() and wait_event_type='Lock' and query like 'select epoch::text,phase%')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("decision did not wait for recovery before locking the device")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Recovery holds the state lock and must still be able to revoke the device.
	if _, err := holder.ExecContext(f.ctx, `update devices set revoked_at=clock_timestamp() where id=$1`, f.ticket.DeviceID); err != nil {
		t.Fatal("decision held the device while waiting for recovery", err)
	}
	if err := holder.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-decided; !errors.Is(err, ErrAccessDenied) {
		t.Fatal("decision ignored the revocation completed ahead of it", err)
	}
	assertApprovalPending(t, f, f.request)
	var count int
	if err := f.database.DB.QueryRowContext(f.ctx, `select count(*) from approval_decision_evidence`).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed decision left evidence", count, err)
	}
}

func TestApprovalEvidenceRequiresExplicitDatabasePrivileges(t *testing.T) {
	f := newApprovalFixture(t)
	role := "dsh_approval_evidence_" + strings.ReplaceAll(approvalTestUUID(t), "-", "")
	if _, err := f.database.DB.ExecContext(f.ctx, "create role "+role+" nologin"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := f.database.DB.ExecContext(ctx, "drop role "+role); err != nil {
			t.Error("fixture role was not removed", err)
		}
	})
	var metadataRead, materialRead bool
	if err := f.database.DB.QueryRowContext(f.ctx, `select has_table_privilege($1,'approval_decision_evidence','select'),has_table_privilege($1,'approval_decision_evidence_material','select')`, role).Scan(&metadataRead, &materialRead); err != nil || metadataRead || materialRead {
		t.Fatal("decision evidence is readable without a grant", metadataRead, materialRead, err)
	}
}

func TestApprovalEvidenceCaptureWorksWithoutMaterialReadPrivilege(t *testing.T) {
	f := newApprovalFixture(t)
	f.register(t, f.request)
	compact := f.signed(t, f.request, "reject")
	role := "dsh_approval_writer_" + strings.ReplaceAll(approvalTestUUID(t), "-", "")
	if _, err := f.database.DB.ExecContext(f.ctx, "create role "+role+" nologin"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := f.database.DB.ExecContext(ctx, "reset role"); err != nil {
			t.Error("fixture role was not reset", err)
			return
		}
		if _, err := f.database.DB.ExecContext(ctx, "drop owned by "+role); err != nil {
			t.Error("fixture privileges were not removed", err)
			return
		}
		if _, err := f.database.DB.ExecContext(ctx, "drop role "+role); err != nil {
			t.Error("fixture role was not removed", err)
		}
	})
	statements := []string{
		"grant usage on schema public to " + role,
		"grant select,insert,update on all tables in schema public to " + role,
		"grant usage,select on all sequences in schema public to " + role,
		"revoke all on approval_decision_evidence,approval_decision_evidence_material from " + role,
		"grant select,insert on approval_decision_evidence to " + role,
		"grant insert on approval_decision_evidence_material to " + role,
		"revoke update on remote_recovery_state from " + role,
		"grant update(slot) on remote_recovery_state to " + role,
	}
	for _, statement := range statements {
		if _, err := f.database.DB.ExecContext(f.ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	// Keep the SET ROLE and the application transaction on one pooled session.
	f.database.DB.SetMaxOpenConns(1)
	if _, err := f.database.DB.ExecContext(f.ctx, "set role "+role); err != nil {
		t.Fatal(err)
	}
	if status, err := f.control.Decide(f.ctx, f.principal, f.ticket, approvalRaw(t, f.request), compact); err != nil || status.State != "denied" {
		t.Fatal("limited writer could not capture decision evidence", err)
	}
	if _, err := f.database.DB.ExecContext(f.ctx, `select public_jwk from approval_decision_evidence_material`); err == nil {
		t.Fatal("writer unexpectedly read protected evidence material")
	}
	if _, err := f.database.DB.ExecContext(f.ctx, `update remote_recovery_state set epoch='ffffffff-ffff-4fff-8fff-ffffffffffff'`); err == nil {
		t.Fatal("decision writer unexpectedly changed the recovery epoch")
	}
}
