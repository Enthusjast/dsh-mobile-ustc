package store

import (
	"errors"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/files"
)

func scanMutationSnapshot(t *testing.T, h *fileFixture) string {
	t.Helper()
	var snapshot string
	if err := h.database.DB.QueryRowContext(h.ctx, `select jsonb_build_object(
	 'files',(select jsonb_agg(to_jsonb(f) order by id) from files f),
	 'transfers',(select jsonb_agg(to_jsonb(t) order by file_id) from file_transfers t),
	 'attempts',(select jsonb_agg(to_jsonb(a) order by id) from file_scan_attempts a),
	 'objects',(select jsonb_agg(to_jsonb(o) order by object_key) from file_objects o),
	 'audit',(select jsonb_agg(to_jsonb(a) order by id) from audit_log a where action like 'file.%'),
	 'events',(select jsonb_agg(to_jsonb(e) order by id) from control_outbox e where topic in('file.clean','file.export.clean'))
	 )::text`).Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestFileScanDeadlinesCannotSurviveMutationAuditOrOutboxWaits(t *testing.T) {
	for _, operation := range []string{"claim", "renew", "renew-new-lease", "complete-state", "complete-audit", "complete-outbox", "fail-retry", "fail-terminal"} {
		for _, expiry := range []string{"grant", "file", "retain", "lease"} {
			if operation == "renew-new-lease" && expiry != "lease" || (operation == "fail-retry" || operation == "fail-terminal") && expiry == "grant" {
				continue
			}
			t.Run(operation+"/"+expiry, func(t *testing.T) {
				h := newFileFixture(t)
				file := h.scanning(t)
				var claim files.ScanClaim
				if operation != "claim" {
					claim = h.claim(t)
				}
				h.exec(t, `create table scan_deadline_fixture(deadline timestamptz not null)`)
				table, event, condition, fragment, prefix := "file_transfers", "update", "new.scan_attempts>old.scan_attempts", "update file_transfers set scan_attempts", ""
				switch operation {
				case "claim":
					if expiry == "lease" {
						h.exec(t, `create function shorten_scan_deadline() returns trigger language plpgsql as $$ begin
						 new.lease_until=(select deadline from scan_deadline_fixture);return new;end $$;
						 create trigger shorten_scan_deadline before insert on file_scan_attempts for each row execute function shorten_scan_deadline()`)
					}
				case "renew", "renew-new-lease":
					table, condition, fragment = "file_scan_attempts", "true", "update file_scan_attempts set lease_until"
					if operation == "renew-new-lease" {
						prefix = `new.lease_until=least(new.lease_until,(select deadline from scan_deadline_fixture));`
					}
				case "complete-state":
					table, condition, fragment = "files", "old.state='scanning' and new.state='clean'", "update files set state='clean'"
				case "complete-audit":
					table, event, condition, fragment = "audit_log", "insert", "new.action='file.scan_clean'", "insert into audit_log"
				case "complete-outbox":
					table, event, condition, fragment = "control_outbox", "insert", "new.topic='file.clean'", "insert into control_outbox"
				case "fail-retry":
					table, event, condition, fragment = "audit_log", "insert", "new.action='file.scan_deferred'", "insert into audit_log"
				case "fail-terminal":
					table, event, condition, fragment = "audit_log", "insert", "new.action='file.scan_rejected'", "insert into audit_log"
				}
				h.exec(t, `create function hold_scan_deadline() returns trigger language plpgsql as $$ begin `+prefix+`
				 if `+condition+` then perform pg_advisory_xact_lock(426967);end if;return new;end $$;
				 create trigger hold_scan_deadline before `+event+` on `+table+` for each row execute function hold_scan_deadline()`)
				var deadline time.Time
				if err := h.database.DB.QueryRowContext(h.ctx, `insert into scan_deadline_fixture values(clock_timestamp()+interval '600 milliseconds') returning deadline`).Scan(&deadline); err != nil {
					t.Fatal(err)
				}
				want := files.ErrStale
				switch expiry {
				case "grant":
					want = files.ErrAccess
					h.exec(t, `update runtime_grants set expires_at=$1`, deadline)
				case "file":
					h.exec(t, `update files set expires_at=$1 where id=$2`, deadline, file.ID)
				case "retain":
					h.exec(t, `update file_transfers set retain_until=$1 where file_id=$2`, deadline, file.ID)
				case "lease":
					if operation != "claim" && operation != "renew-new-lease" {
						h.exec(t, `update file_scan_attempts set lease_until=$1 where id=$2`, deadline, claim.AttemptID)
					}
				}
				before := scanMutationSnapshot(t, h)
				gate, err := h.database.DB.BeginTx(h.ctx, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer gate.Rollback()
				if _, err := gate.ExecContext(h.ctx, `select pg_advisory_xact_lock(426967)`); err != nil {
					t.Fatal(err)
				}
				result := make(chan error, 1)
				go func() {
					var err error
					switch operation {
					case "claim":
						var current *files.ScanClaim
						current, err = h.repository.ClaimScan(h.ctx, fileTestPolicy)
						if err != nil && current != nil {
							result <- errors.New("denied scan returned candidate authority")
							return
						}
					case "renew", "renew-new-lease":
						var until time.Time
						until, err = h.repository.RenewScan(h.ctx, claim)
						if err != nil && !until.IsZero() {
							result <- errors.New("denied scan renewal returned a deadline")
							return
						}
					case "fail-retry", "fail-terminal":
						err = h.repository.FailScan(h.ctx, claim, "storage_unavailable", operation == "fail-retry")
					default:
						err = h.repository.CompleteScan(h.ctx, claim)
					}
					result <- err
				}()
				waitForGrantLock(t, h.ctx, h.database, fragment)
				waitForGrantDatabaseExpiry(t, h.ctx, h.database, deadline)
				if err := gate.Commit(); err != nil {
					t.Fatal(err)
				}
				if err := <-result; !errors.Is(err, want) {
					t.Fatal("expired scan authority survived its database wait", err)
				}
				if after := scanMutationSnapshot(t, h); before != after {
					t.Fatal("expired scan changed file, candidate, retry, audit or publication facts")
				}
			})
		}
	}
}

func TestFileScanIgnoredEvidenceWritesRollBackAndRemainRetryable(t *testing.T) {
	for _, fault := range []struct{ name, operation, table, event, condition string }{
		{"claim-attempt", "claim", "file_scan_attempts", "insert", "true"},
		{"claim-candidate", "claim", "file_objects", "insert", "new.kind='objects'"},
		{"claim-budget", "claim", "file_transfers", "update", "new.scan_attempts>old.scan_attempts"},
		{"renew", "renew", "file_scan_attempts", "update", "true"},
		{"clean-file", "complete", "files", "update", "new.state='clean'"},
		{"clean-origin", "complete", "file_transfers", "update", "new.committed_attempt_id is not null"},
		{"clean-attempt", "complete", "file_scan_attempts", "update", "new.state='clean'"},
		{"clean-candidate", "complete", "file_objects", "update", "new.kind='objects'"},
		{"clean-audit", "complete", "audit_log", "insert", "new.action='file.scan_clean'"},
		{"clean-outbox", "complete", "control_outbox", "insert", "new.topic='file.clean'"},
		{"failed-attempt", "retry", "file_scan_attempts", "update", "new.state='failed'"},
		{"failed-candidate", "retry", "file_objects", "update", "new.kind='objects'"},
		{"retry-budget", "retry", "file_transfers", "update", "new.error_code='storage_unavailable'"},
		{"retry-audit", "retry", "audit_log", "insert", "new.action='file.scan_deferred'"},
		{"rejected-file", "reject", "files", "update", "new.state='rejected'"},
		{"rejected-origin", "reject", "file_transfers", "update", "new.error_code='storage_unavailable'"},
		{"rejected-audit", "reject", "audit_log", "insert", "new.action='file.scan_rejected'"},
	} {
		t.Run(fault.name, func(t *testing.T) {
			h := newFileFixture(t)
			h.scanning(t)
			var claim files.ScanClaim
			if fault.operation != "claim" {
				claim = h.claim(t)
			}
			h.exec(t, `create function ignore_scan_write() returns trigger language plpgsql as $$ begin
			 if `+fault.condition+` then return null;end if;return new;end $$;
			 create trigger ignore_scan_write before `+fault.event+` on `+fault.table+` for each row execute function ignore_scan_write()`)
			before := scanMutationSnapshot(t, h)
			run := func() error {
				switch fault.operation {
				case "claim":
					current, err := h.repository.ClaimScan(h.ctx, fileTestPolicy)
					if err != nil && current != nil {
						return errors.New("ignored write returned scan candidate authority")
					}
					return err
				case "renew":
					until, err := h.repository.RenewScan(h.ctx, claim)
					if err != nil && !until.IsZero() {
						return errors.New("ignored write returned renewal authority")
					}
					return err
				case "complete":
					return h.repository.CompleteScan(h.ctx, claim)
				default:
					return h.repository.FailScan(h.ctx, claim, "storage_unavailable", fault.operation == "retry")
				}
			}
			if err := run(); !errors.Is(err, files.ErrUnavailable) {
				t.Fatal("missing scan evidence was reported as committed", err)
			}
			if scanMutationSnapshot(t, h) != before {
				t.Fatal("missing scan evidence left a partial transaction")
			}
			h.exec(t, `drop trigger ignore_scan_write on `+fault.table+`;drop function ignore_scan_write()`)
			if err := run(); err != nil {
				t.Fatal("restored scan evidence could not be retried", err)
			}
		})
	}
}

func TestFileScanCommittedCompletionRetryIsHistoryAndCannotRenewAuthority(t *testing.T) {
	h := newFileFixture(t)
	h.scanning(t)
	claim := h.claim(t)
	if err := h.repository.CompleteScan(h.ctx, claim); err != nil {
		t.Fatal(err)
	}
	h.exec(t, `update file_scan_attempts set lease_until=clock_timestamp()-interval '1 second' where id=$1`, claim.AttemptID)
	h.exec(t, `update devices set revoked_at=clock_timestamp() where id=$1`, h.actor.DeviceID)
	before := scanMutationSnapshot(t, h)
	if err := h.repository.CompleteScan(h.ctx, claim); err != nil {
		t.Fatal("historical completion required fresh scan authority", err)
	}
	if scanMutationSnapshot(t, h) != before {
		t.Fatal("historical completion rewrote evidence or deadlines")
	}
	if _, err := h.repository.RenewScan(h.ctx, claim); !errors.Is(err, files.ErrAccess) {
		t.Fatal("historical completion restored revoked scan authority", err)
	}
}
