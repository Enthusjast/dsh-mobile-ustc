package store

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/coldarchive"
	"dsh-mobile-ustc/services/remote/internal/testsupport"
)

func applyColdHistoryImportFixtureMigration(t *testing.T, ctx context.Context, db *Postgres, direction string) {
	t.Helper()
	if direction != "up" && direction != "down" {
		t.Fatal("invalid fixture migration direction")
	}
	raw, err := os.ReadFile("../../../../deploy/sql/030_cold_history_imports." + direction + ".sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, string(raw)); err != nil {
		t.Fatal("cold history import fixture migration failed", err)
	}
}

func coldHistoryFixture(t *testing.T, kind string, expired bool) (context.Context, *Postgres, ColdHistoryImportRequest, []byte, string) {
	t.Helper()
	var artifact []byte
	var key *coldarchive.Key
	var domain, exportID, source string
	switch kind {
	case "audit":
		ctx, db, request, _ := auditColdFixture(t)
		if expired {
			expireAuditBatchFixture(t, ctx, db, request.BatchID)
		}
		_, raw, err := db.PrepareAuditColdExport(ctx, request)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.FinishAuditColdExport(ctx, request, coldarchive.Digest(raw), len(raw)); err != nil {
			t.Fatal(err)
		}
		artifact, key, domain, exportID, source = raw, request.Key, request.DomainID, request.ExportID, "PRIVATE_AUDIT_COLD_BODY"
	case "approval":
		f, request, compact := evidenceExportFixture(t)
		if expired {
			expireEvidenceFixture(t, f)
		}
		_, raw, err := f.database.PrepareEvidenceExport(f.ctx, request)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.database.FinishEvidenceExport(f.ctx, request, coldarchive.Digest(raw), len(raw)); err != nil {
			t.Fatal(err)
		}
		artifact, key, domain, exportID, source = raw, request.Key, request.DomainID, request.ExportID, compact
	default:
		t.Fatal("invalid fixture kind")
	}
	t.Cleanup(func() { clear(artifact) })
	ctx, target := newPostgresIntegrationDatabase(t)
	request := ColdHistoryImportRequest{Kind: kind, ImportID: approvalTestUUID(t), ExportID: exportID, DomainID: domain, DatabaseEpoch: OriginalDatabaseEpoch,
		AccessFingerprint: strings.Repeat("b", 64), Key: key}
	return ctx, target, request, artifact, source
}

func TestColdHistoryImportPreservesInertAuditAndApprovalEvidence(t *testing.T) {
	for _, kind := range []string{"audit", "approval"} {
		t.Run(kind, func(t *testing.T) {
			ctx, target, request, artifact, source := coldHistoryFixture(t, kind, false)
			seedGrantFixture(t, ctx, target.DB)
			live := archiveFixtureEvent(t, ctx, target.DB, "device.revoked", "2000-01-01T00:00:00Z", "")
			var before string
			if err := target.DB.QueryRowContext(ctx, `select to_jsonb(g)::text from runtime_grants g where revoked_at is null limit 1`).Scan(&before); err != nil {
				t.Fatal(err)
			}
			result, err := target.ImportColdHistory(ctx, request, artifact)
			if err != nil || result.Kind != kind || result.Entries != 1 || result.ImportID != request.ImportID {
				t.Fatal("cold history import failed", err)
			}
			var captured string
			if kind == "audit" {
				if err := target.DB.QueryRowContext(ctx, `select payload->'entries'->0->>'source_base64' from cold_history_import_payloads where import_id=$1`, request.ImportID).Scan(&captured); err != nil {
					t.Fatal(err)
				}
				decoded, err := base64.StdEncoding.DecodeString(captured)
				if err != nil || !bytes.Contains(decoded, []byte(source)) {
					t.Fatal("audit source was not preserved", err)
				}
				clear(decoded)
			} else if err := target.DB.QueryRowContext(ctx, `select payload->'proof'->>'decision_jws' from cold_history_import_payloads where import_id=$1`, request.ImportID).Scan(&captured); err != nil || captured != source {
				t.Fatal("approval signature was not preserved", err)
			}
			var after string
			var outbox, approvals, evidence, archivedAudits, recoveries int
			if err := target.DB.QueryRowContext(ctx, `select (select to_jsonb(g)::text from runtime_grants g where revoked_at is null limit 1),
			 (select count(*) from control_outbox where id=$1),(select count(*) from approvals),(select count(*) from approval_decision_evidence),
			 (select count(*) from audit_log where action='fixture.event'),(select count(*) from remote_recovery_runs)`, live).
				Scan(&after, &outbox, &approvals, &evidence, &archivedAudits, &recoveries); err != nil || after != before || outbox != 1 || approvals != 0 || evidence != 0 || archivedAudits != 0 || recoveries != 0 {
				t.Fatal("historical import changed live state", outbox, approvals, evidence, archivedAudits, recoveries, err)
			}
			retry, err := target.ImportColdHistory(ctx, request, artifact)
			if err != nil || !retry.ImportedAt.Equal(result.ImportedAt) || retry.ArtifactSHA256 != result.ArtifactSHA256 {
				t.Fatal("history import retry was not stable", err)
			}
			var imports, verified int
			if err := target.DB.QueryRowContext(ctx, `select count(*) filter(where action='cold.history.import'),count(*) filter(where action='cold.history.import.verified') from audit_log`).Scan(&imports, &verified); err != nil || imports != 1 || verified != 1 {
				t.Fatal("history import audit was missing or duplicated", imports, verified, err)
			}
			for _, statement := range []string{`update cold_history_import_payloads set payload='{}'::jsonb`, `delete from cold_history_import_payloads`, `delete from cold_history_imports`, `truncate cold_history_import_payloads`} {
				if _, err := target.DB.ExecContext(ctx, statement); err == nil {
					t.Fatal("unexpired historical document was modified")
				}
			}
		})
	}
}

func TestColdHistoryImportRejectsWrongTypeDomainKeyAndTampering(t *testing.T) {
	for _, kind := range []string{"audit", "approval"} {
		t.Run(kind, func(t *testing.T) {
			ctx, target, request, artifact, _ := coldHistoryFixture(t, kind, false)
			modified := append([]byte(nil), artifact...)
			modified[len(modified)-1] ^= 1
			if _, err := target.ImportColdHistory(ctx, request, modified); !errors.Is(err, ErrColdHistoryImportInvalid) {
				t.Fatal("tampered artifact was accepted", err)
			}
			wrong := request
			wrong.Key = exportFixtureKey(t, 56)
			if _, err := target.ImportColdHistory(ctx, wrong, artifact); !errors.Is(err, ErrColdHistoryImportInvalid) {
				t.Fatal("wrong key was accepted", err)
			}
			wrong = request
			wrong.DomainID = approvalTestUUID(t)
			if _, err := target.ImportColdHistory(ctx, wrong, artifact); !errors.Is(err, ErrColdHistoryImportInvalid) {
				t.Fatal("wrong domain was accepted", err)
			}
			wrong = request
			if kind == "audit" {
				wrong.Kind = "approval"
			} else {
				wrong.Kind = "audit"
			}
			if _, err := target.ImportColdHistory(ctx, wrong, artifact); !errors.Is(err, ErrColdHistoryImportInvalid) {
				t.Fatal("archive type confusion was accepted", err)
			}
			var count int
			if err := target.DB.QueryRowContext(ctx, `select count(*) from cold_history_imports`).Scan(&count); err != nil || count != 0 {
				t.Fatal("invalid input changed historical state", count, err)
			}
		})
	}
}

func TestColdHistoryAuditImportPreservesUnknownLegacyOrigin(t *testing.T) {
	ctx, source := newPostgresIntegrationDatabase(t)
	enableAuditFixtureTime(t, ctx, source.DB)
	id := auditFixtureEntry(t, ctx, source.DB, "2000-01-01T00:00:00Z", "legacy")
	tx, err := source.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `alter table audit_log disable trigger audit_log_immutable`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `update audit_log set database_epoch=null,producer_xid=null where id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `alter table audit_log enable trigger audit_log_immutable`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	batch, err := source.ArchiveAuditHistory(ctx, auditArchiveFixtureRequest(t))
	if err != nil || batch.Entries != 1 {
		t.Fatal(err)
	}
	export := AuditColdExportRequest{ExportID: approvalTestUUID(t), DomainID: approvalTestUUID(t), DatabaseEpoch: OriginalDatabaseEpoch, BatchID: batch.BatchID,
		DestinationFingerprint: strings.Repeat("a", 64), Key: exportFixtureKey(t, 57)}
	_, artifact, err := source.PrepareAuditColdExport(ctx, export)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.FinishAuditColdExport(ctx, export, coldarchive.Digest(artifact), len(artifact)); err != nil {
		t.Fatal(err)
	}
	targetCtx, target := newPostgresIntegrationDatabase(t)
	request := ColdHistoryImportRequest{Kind: "audit", ImportID: approvalTestUUID(t), ExportID: export.ExportID, DomainID: export.DomainID, DatabaseEpoch: OriginalDatabaseEpoch,
		AccessFingerprint: strings.Repeat("b", 64), Key: export.Key}
	result, err := target.ImportColdHistory(targetCtx, request, artifact)
	if err != nil || result.SourceEpoch != OriginalDatabaseEpoch {
		t.Fatal("legacy audit document was not imported", err)
	}
	var unknown bool
	if err := target.DB.QueryRowContext(targetCtx, `select payload->'entries'->0->'source_epoch'='null'::jsonb
	 and (convert_from(decode(payload->'entries'->0->>'source_base64','base64'),'UTF8')::jsonb)->'database_epoch'='null'::jsonb
	 from cold_history_import_payloads where import_id=$1`, request.ImportID).Scan(&unknown); err != nil || !unknown {
		t.Fatal("legacy event origin was invented during import", err)
	}
}

func TestColdHistoryImportAuditFailureRollsBackAllRows(t *testing.T) {
	ctx, target, request, artifact, _ := coldHistoryFixture(t, "audit", false)
	if _, err := target.DB.ExecContext(ctx, `create function test_fail_cold_history_audit() returns trigger language plpgsql as $$
	 begin if new.action='cold.history.import' then raise exception 'fixture failure'; end if; return null; end $$;
	 create constraint trigger test_fail_cold_history_audit after insert on audit_log deferrable initially deferred
	 for each row execute function test_fail_cold_history_audit()`); err != nil {
		t.Fatal(err)
	}
	if _, err := target.ImportColdHistory(ctx, request, artifact); !errors.Is(err, ErrDatabaseUnavailable) {
		t.Fatal("import ignored deferred audit failure", err)
	}
	var headers, payloads, audits int
	if err := target.DB.QueryRowContext(ctx, `select (select count(*) from cold_history_imports),
	 (select count(*) from cold_history_import_payloads),(select count(*) from audit_log where action='cold.history.import')`).Scan(&headers, &payloads, &audits); err != nil || headers != 0 || payloads != 0 || audits != 0 {
		t.Fatal("failed commit left partial history", headers, payloads, audits, err)
	}
	if _, err := target.DB.ExecContext(ctx, `drop trigger test_fail_cold_history_audit on audit_log; drop function test_fail_cold_history_audit()`); err != nil {
		t.Fatal(err)
	}
	if _, err := target.ImportColdHistory(ctx, request, artifact); err != nil {
		t.Fatal("failed import could not be retried", err)
	}
}

func TestColdHistoryImportConcurrentRetriesShareOneIdentity(t *testing.T) {
	ctx, target, request, artifact, _ := coldHistoryFixture(t, "approval", false)
	type outcome struct {
		result ColdHistoryImportResult
		err    error
	}
	results := make(chan outcome, 4)
	var group sync.WaitGroup
	for range 4 {
		group.Go(func() {
			result, err := target.ImportColdHistory(ctx, request, artifact)
			results <- outcome{result, err}
		})
	}
	group.Wait()
	close(results)
	var first ColdHistoryImportResult
	for item := range results {
		if item.err != nil {
			t.Fatal(item.err)
		}
		if first.ImportID == "" {
			first = item.result
		} else if !first.ImportedAt.Equal(item.result.ImportedAt) || first.ArtifactSHA256 != item.result.ArtifactSHA256 {
			t.Fatal("concurrent retry changed its import identity")
		}
	}
	other := request
	other.ImportID = approvalTestUUID(t)
	if _, err := target.ImportColdHistory(ctx, other, artifact); !errors.Is(err, ErrColdHistoryImportConflict) {
		t.Fatal("same artifact was claimed by another operation", err)
	}
	var headers, payloads, imports int
	if err := target.DB.QueryRowContext(ctx, `select (select count(*) from cold_history_imports),
	 (select count(*) from cold_history_import_payloads),(select count(*) from audit_log where action='cold.history.import')`).Scan(&headers, &payloads, &imports); err != nil || headers != 1 || payloads != 1 || imports != 1 {
		t.Fatal("concurrent history import was duplicated", headers, payloads, imports, err)
	}
}

func TestColdHistoryImportConcurrentDifferentIDsClaimOnlyOneArtifact(t *testing.T) {
	ctx, target, request, artifact, _ := coldHistoryFixture(t, "audit", false)
	other := request
	other.ImportID = approvalTestUUID(t)
	results := make(chan error, 2)
	var group sync.WaitGroup
	for _, candidate := range []ColdHistoryImportRequest{request, other} {
		group.Go(func() {
			_, err := target.ImportColdHistory(ctx, candidate, artifact)
			results <- err
		})
	}
	group.Wait()
	close(results)
	accepted, conflicts := 0, 0
	for err := range results {
		switch {
		case err == nil:
			accepted++
		case errors.Is(err, ErrColdHistoryImportConflict):
			conflicts++
		default:
			t.Fatal("concurrent claim failed unexpectedly", err)
		}
	}
	var headers, imported, denied int
	if err := target.DB.QueryRowContext(ctx, `select (select count(*) from cold_history_imports),
	 (select count(*) from audit_log where action='cold.history.import'),
	 (select count(*) from audit_log where action='cold.history.import.conflict' and result='failure')`).Scan(&headers, &imported, &denied); err != nil || accepted != 1 || conflicts != 1 || headers != 1 || imported != 1 || denied != 1 {
		t.Fatal("concurrent artifact claims were not serialized", accepted, conflicts, headers, imported, denied, err)
	}
}

func TestColdHistoryImportRejectsIncompleteOrCorruptedStoredHistory(t *testing.T) {
	ctx, target, request, artifact, _ := coldHistoryFixture(t, "audit", false)
	if _, err := target.ImportColdHistory(ctx, request, artifact); err != nil {
		t.Fatal(err)
	}
	if _, err := target.DB.ExecContext(ctx, `insert into cold_history_imports(id,kind,domain_id,export_id,object_id,source_epoch,operation_epoch,target_epoch,key_id,key_fingerprint,
	 artifact_sha256,artifact_size,payload_sha256,entry_count,retain_until,imported_at)
	 select $1,kind,domain_id,$2,object_id,source_epoch,operation_epoch,target_epoch,key_id,key_fingerprint,artifact_sha256,artifact_size,payload_sha256,entry_count,retain_until,clock_timestamp()
	 from cold_history_imports where id=$3`, approvalTestUUID(t), approvalTestUUID(t), request.ImportID); err == nil {
		t.Fatal("history identity committed without its payload")
	}
	tx, err := target.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `alter table cold_history_import_payloads disable trigger cold_history_import_payload_guard`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `update cold_history_import_payloads set payload=jsonb_set(payload,'{batch,id}',to_jsonb($2::text)) where import_id=$1`, request.ImportID, approvalTestUUID(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `alter table cold_history_import_payloads enable trigger cold_history_import_payload_guard`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := target.ImportColdHistory(ctx, request, artifact); !errors.Is(err, ErrColdHistoryImportConflict) {
		t.Fatal("retry accepted corrupted stored history", err)
	}
	var conflicts int
	if err := target.DB.QueryRowContext(ctx, `select count(*) from audit_log where action='cold.history.import.conflict' and result='failure' and metadata->>'current_epoch'=$1`, request.DatabaseEpoch).Scan(&conflicts); err != nil || conflicts != 1 {
		t.Fatal("conflicting history read was not audited", conflicts, err)
	}
}

func TestColdHistoryImportExpiredDeletionCannotResurrect(t *testing.T) {
	for _, kind := range []string{"audit", "approval"} {
		t.Run(kind, func(t *testing.T) {
			ctx, target, request, artifact, _ := coldHistoryFixture(t, kind, true)
			if _, err := target.ImportColdHistory(ctx, request, artifact); err != nil {
				t.Fatal(err)
			}
			var payload string
			if err := target.DB.QueryRowContext(ctx, `select payload::text from cold_history_import_payloads where import_id=$1`, request.ImportID).Scan(&payload); err != nil {
				t.Fatal(err)
			}
			if _, err := target.DB.ExecContext(ctx, `create function test_fail_cold_history_delete() returns trigger language plpgsql as $$
			 begin if new.action='cold.history.import.delete' then raise exception 'fixture failure'; end if; return new; end $$;
			 create trigger test_fail_cold_history_delete before insert on audit_log for each row execute function test_fail_cold_history_delete()`); err != nil {
				t.Fatal(err)
			}
			if _, err := target.DB.ExecContext(ctx, `delete from cold_history_import_payloads where import_id=$1`, request.ImportID); err == nil {
				t.Fatal("expired deletion ignored audit failure")
			}
			var present int
			if err := target.DB.QueryRowContext(ctx, `select count(*) from cold_history_import_payloads where import_id=$1`, request.ImportID).Scan(&present); err != nil || present != 1 {
				t.Fatal("failed audit removed historical payload", present, err)
			}
			if _, err := target.DB.ExecContext(ctx, `drop trigger test_fail_cold_history_delete on audit_log; drop function test_fail_cold_history_delete()`); err != nil {
				t.Fatal(err)
			}
			if _, err := target.DB.ExecContext(ctx, `delete from cold_history_import_payloads where import_id=$1`, request.ImportID); err != nil {
				t.Fatal(err)
			}
			if _, err := target.ImportColdHistory(ctx, request, artifact); !errors.Is(err, ErrColdHistoryImportExpired) {
				t.Fatal("retry resurrected deleted history", err)
			}
			other := request
			other.ImportID = approvalTestUUID(t)
			if _, err := target.ImportColdHistory(ctx, other, artifact); !errors.Is(err, ErrColdHistoryImportConflict) {
				t.Fatal("new operation resurrected deleted history", err)
			}
			if _, err := target.DB.ExecContext(ctx, `insert into cold_history_import_payloads(import_id,payload) values($1,$2::jsonb)`, request.ImportID, payload); err == nil {
				t.Fatal("direct insertion resurrected deleted history")
			}
			var headers, deletes, expiredAudits, conflicts int
			if err := target.DB.QueryRowContext(ctx, `select (select count(*) from cold_history_imports),
			 (select count(*) from audit_log where action='cold.history.import.delete'),
			 (select count(*) from audit_log where action='cold.history.import.expired' and result='failure'),
			 (select count(*) from audit_log where action='cold.history.import.conflict' and result='failure')`).Scan(&headers, &deletes, &expiredAudits, &conflicts); err != nil || headers != 1 || deletes != 1 || expiredAudits != 1 || conflicts != 1 {
				t.Fatal("expiry lost its identity or audit", headers, deletes, expiredAudits, conflicts, err)
			}
			down, err := os.ReadFile("../../../../deploy/sql/030_cold_history_imports.down.sql")
			if err != nil {
				t.Fatal(err)
			}
			conn, err := target.DB.Conn(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, err := conn.ExecContext(ctx, string(down)); err == nil {
				t.Fatal("migration erased retained import identity")
			}
			if _, err := conn.ExecContext(ctx, `rollback`); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestColdHistoryImportRetrySerializesWithExpiredDeletion(t *testing.T) {
	ctx, target, request, artifact, _ := coldHistoryFixture(t, "audit", true)
	target.DB.SetMaxOpenConns(5)
	if _, err := target.ImportColdHistory(ctx, request, artifact); err != nil {
		t.Fatal(err)
	}
	if _, err := target.DB.ExecContext(ctx, `create function test_wait_cold_history_retry() returns trigger language plpgsql as $$
	 begin if new.action='cold.history.import.verified' then perform pg_advisory_xact_lock(763207); end if; return new; end $$;
	 create trigger test_wait_cold_history_retry before insert on audit_log for each row execute function test_wait_cold_history_retry()`); err != nil {
		t.Fatal(err)
	}
	holder, err := target.DB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if _, err := holder.ExecContext(ctx, `select pg_advisory_lock(763207)`); err != nil {
		t.Fatal(err)
	}
	defer holder.ExecContext(context.Background(), `select pg_advisory_unlock(763207)`)
	verified := make(chan error, 1)
	go func() {
		_, err := target.ImportColdHistory(ctx, request, artifact)
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
				t.Fatal("fixture did not reach the expected cold history lock")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	waitForLock("insert into audit_log%")
	deleted := make(chan error, 1)
	go func() {
		_, err := target.DB.ExecContext(ctx, `delete from cold_history_import_payloads where import_id=$1 /* cold-history-expiry */`, request.ImportID)
		deleted <- err
	}()
	waitForLock("delete from cold_history_import_payloads%cold-history-expiry%")
	if _, err := holder.ExecContext(ctx, `select pg_advisory_unlock(763207)`); err != nil {
		t.Fatal(err)
	}
	if err := <-verified; err != nil {
		t.Fatal("history verification did not commit before deletion", err)
	}
	if err := <-deleted; err != nil {
		t.Fatal("expired deletion did not proceed", err)
	}
	if _, err := target.ImportColdHistory(ctx, request, artifact); !errors.Is(err, ErrColdHistoryImportExpired) {
		t.Fatal("later retry missed deletion", err)
	}
}

func TestColdHistoryImportPreventsOutOfOrderExportMigrationRollback(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	conn, err := db.DB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, name := range []string{"028_approval_evidence_exports", "029_audit_cold_exports"} {
		down, err := os.ReadFile("../../../../deploy/sql/" + name + ".down.sql")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.ExecContext(ctx, string(down)); err == nil {
			t.Fatal("source export schema was removed under importer", name)
		}
		if _, err := conn.ExecContext(ctx, `rollback`); err != nil {
			t.Fatal(err)
		}
	}
}

func TestColdHistoryImportLimitedRoleCannotMutateHistoryOrRecoveryEpoch(t *testing.T) {
	ctx, target, request, artifact, _ := coldHistoryFixture(t, "approval", false)
	role := "dsh_cold_history_" + strings.ReplaceAll(approvalTestUUID(t), "-", "")
	if _, err := target.DB.ExecContext(ctx, "create role "+role+" nologin"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := target.DB.ExecContext(cleanup, "reset role"); err != nil {
			t.Error(err)
			return
		}
		if _, err := target.DB.ExecContext(cleanup, "drop owned by "+role); err != nil {
			t.Error(err)
			return
		}
		if _, err := target.DB.ExecContext(cleanup, "drop role "+role); err != nil {
			t.Error(err)
		}
	})
	for _, statement := range []string{
		"grant usage on schema public to " + role,
		"grant select,insert on cold_history_imports,cold_history_import_payloads to " + role,
		"grant update(import_id) on cold_history_import_payloads to " + role,
		"grant select,update(slot) on remote_recovery_state to " + role,
		"grant insert(actor_type,actor_id,action,result,metadata) on audit_log to " + role,
		"grant usage,select on sequence audit_log_id_seq to " + role,
	} {
		if _, err := target.DB.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	target.DB.SetMaxOpenConns(1)
	if _, err := target.DB.ExecContext(ctx, "set role "+role); err != nil {
		t.Fatal(err)
	}
	if _, err := target.ImportColdHistory(ctx, request, artifact); err != nil {
		t.Fatal("limited role could not import", err)
	}
	if _, err := target.ImportColdHistory(ctx, request, artifact); err != nil {
		t.Fatal("limited role could not verify a retry", err)
	}
	if _, err := target.DB.ExecContext(ctx, `update cold_history_import_payloads set import_id=import_id`); err == nil {
		t.Fatal("row-lock privilege allowed historical mutation")
	}
	if _, err := target.DB.ExecContext(ctx, `update remote_recovery_state set epoch='ffffffff-ffff-4fff-8fff-ffffffffffff'`); err == nil {
		t.Fatal("importer changed recovery epoch")
	}
}

func TestColdHistoryImportAfterActualRestoreDoesNotReviveAuthority(t *testing.T) {
	for _, kind := range []string{"audit", "approval"} {
		t.Run(kind, func(t *testing.T) {
			ctx, target, request, artifact, _ := coldHistoryFixture(t, kind, false)
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
			result, err := restored.ImportColdHistory(restoredCtx, request, artifact)
			if err != nil || result.TargetEpoch != epoch || result.SourceEpoch != OriginalDatabaseEpoch {
				t.Fatal("history could not be imported into released recovery", err)
			}
			var active, approvals, evidence, sourceAudits, recoveries, histories int
			if err := database.QueryRowContext(restoredCtx, `select (select count(*) from runtime_grants where revoked_at is null),
			 (select count(*) from approvals),(select count(*) from approval_decision_evidence),
			 (select count(*) from audit_log where action='fixture.event'),(select count(*) from remote_recovery_runs),
			 (select count(*) from cold_history_import_payloads)`).Scan(&active, &approvals, &evidence, &sourceAudits, &recoveries, &histories); err != nil || active != 0 || approvals != 0 || evidence != 0 || sourceAudits != 0 || recoveries != 1 || histories != 1 {
				t.Fatal("historical import revived live state", active, approvals, evidence, sourceAudits, recoveries, histories, err)
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
			if _, err := restored.ImportColdHistory(restoredCtx, request, artifact); !errors.Is(err, ErrColdHistoryImportConflict) {
				t.Fatal("completed import was rebound to a later epoch", err)
			}
			if err := database.QueryRowContext(restoredCtx, `select count(*) from cold_history_import_payloads`).Scan(&histories); err != nil || histories != 1 {
				t.Fatal("later recovery lost imported history", histories, err)
			}
		})
	}
}
