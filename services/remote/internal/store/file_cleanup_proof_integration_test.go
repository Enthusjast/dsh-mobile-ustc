package store

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/files"
)

func TestFileCleanupCannotClaimCandidateWhileItsRenewalCommitIsPending(t *testing.T) {
	h := newFileFixture(t)
	h.scanning(t)
	scan := h.claim(t)
	h.exec(t, `update file_objects set cleanup_after=clock_timestamp()-interval '1 second' where kind='objects'`)
	var oldLease time.Time
	if err := h.database.DB.QueryRowContext(h.ctx, `update file_scan_attempts set lease_until=clock_timestamp()+interval '600 milliseconds' returning lease_until`).Scan(&oldLease); err != nil {
		t.Fatal(err)
	}
	h.exec(t, `create function hold_renewal_commit() returns trigger language plpgsql as $$ begin
	 if new.lease_until>old.lease_until then perform pg_advisory_xact_lock(426969);end if;return null;end $$;
	 create constraint trigger hold_renewal_commit after update on file_scan_attempts deferrable initially deferred for each row execute function hold_renewal_commit()`)
	gate, err := h.database.DB.BeginTx(h.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Rollback()
	if _, err := gate.ExecContext(h.ctx, `select pg_advisory_xact_lock(426969)`); err != nil {
		t.Fatal(err)
	}
	renewed := make(chan error, 1)
	go func() { _, err := h.repository.RenewScan(h.ctx, scan); renewed <- err }()
	waitForGrantLock(t, h.ctx, h.database, "")
	waitForGrantDatabaseExpiry(t, h.ctx, h.database, oldLease)
	// The new lease passed its admission check before the old deadline, but
	// COMMIT still owns the file lock. A snapshot can see the expired old row.
	probe, cancel := context.WithTimeout(h.ctx, 400*time.Millisecond)
	defer cancel()
	if claim, err := h.repository.ClaimDeletion(probe); err != nil || claim != nil {
		t.Fatal("GC claimed the bytes of a scan whose valid renewal still owns the file", err)
	}
	if err := gate.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-renewed; err != nil {
		t.Fatal("renewal admitted before expiry did not commit", err)
	}
	if claim, err := h.repository.ClaimDeletion(h.ctx); err != nil || claim != nil {
		t.Fatal("GC deleted the now-visible active scan candidate", err)
	}
}

func TestFileCleanupProofExpiryRollsBackDeletionAndQuotaWaits(t *testing.T) {
	for _, operation := range []string{"claim", "confirmed", "failed", "quota-lock", "quota-update", "release-marker", "audit"} {
		t.Run(operation, func(t *testing.T) {
			h := newFileFixture(t)
			file, err := h.repository.RegisterUpload(h.ctx, h.actor, h.input)
			if err != nil {
				t.Fatal(err)
			}
			h.expired(t, file.ID)
			var claim files.DeletionClaim
			if operation != "claim" {
				claim = h.deletion(t)
			}
			h.exec(t, `create table cleanup_deadline_fixture(deadline timestamptz not null)`)
			table, event, condition, fragment := "file_objects", "update", "new.lease_id is null", "update file_objects set lease_id=null"
			prefix := ""
			switch operation {
			case "claim":
				condition, fragment = "new.lease_id is not null", "update file_objects set lease_id=$4"
				prefix = `new.lease_until=(select deadline from cleanup_deadline_fixture);`
			case "quota-lock":
				fragment = "select reserved_bytes,reserved_files"
			case "quota-update":
				table, condition, fragment = "file_quota_usage", "new.reserved_files<old.reserved_files", "update file_quota_usage set reserved_bytes"
			case "release-marker":
				table, condition, fragment = "file_transfers", "new.quota_released_at is not null", "update file_transfers set quota_released_at"
			case "audit":
				table, event, condition, fragment = "audit_log", "insert", "new.action='file.quota_released'", "insert into audit_log"
			}
			if operation != "quota-lock" {
				h.exec(t, `create function hold_cleanup_deadline() returns trigger language plpgsql as $$ begin
				 if `+condition+` then `+prefix+` perform pg_advisory_xact_lock(426970);end if;return new;end $$;
				 create trigger hold_cleanup_deadline before `+event+` on `+table+` for each row execute function hold_cleanup_deadline()`)
			}
			var deadline time.Time
			if err := h.database.DB.QueryRowContext(h.ctx, `insert into cleanup_deadline_fixture values(clock_timestamp()+interval '600 milliseconds') returning deadline`).Scan(&deadline); err != nil {
				t.Fatal(err)
			}
			if operation != "claim" {
				h.exec(t, `update file_objects set lease_until=$1 where file_id=$2`, deadline, file.ID)
			}
			before := fileAdmissionSnapshot(t, h)
			gate, err := h.database.DB.BeginTx(h.ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer gate.Rollback()
			if operation == "quota-lock" {
				_, err = gate.ExecContext(h.ctx, `select 1 from file_quota_usage where kind='organization' for update`)
			} else {
				_, err = gate.ExecContext(h.ctx, `select pg_advisory_xact_lock(426970)`)
			}
			if err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() {
				if operation == "claim" {
					current, err := h.repository.ClaimDeletion(h.ctx)
					if err != nil && current != nil {
						result <- errors.New("expired cleanup returned deletion authority")
						return
					}
					result <- err
				} else {
					result <- h.repository.CompleteDeletion(h.ctx, claim, operation != "failed")
				}
			}()
			waitForGrantLock(t, h.ctx, h.database, fragment)
			waitForGrantDatabaseExpiry(t, h.ctx, h.database, deadline)
			if err := gate.Commit(); err != nil {
				t.Fatal(err)
			}
			if err := <-result; !errors.Is(err, files.ErrStale) {
				t.Fatal("expired cleanup lease changed proof or quota", err)
			}
			if fileAdmissionSnapshot(t, h) != before {
				t.Fatal("expired cleanup left deletion, scheduling, quota or audit facts")
			}
			h.quota(t, h.input.SizeBytes, 1)
		})
	}
}

func TestFileCleanupIgnoredProofAndQuotaWritesCannotReportSuccess(t *testing.T) {
	for _, fault := range []struct{ operation, table, event, condition string }{
		{"expire", "files", "update", "new.state='expired'"},
		{"expire", "file_transfers", "update", "new.error_code='expired'"},
		{"expire", "audit_log", "insert", "new.action='file.expired'"},
		{"claim", "file_objects", "update", "new.lease_id is not null"},
		{"confirmed", "file_objects", "update", "new.lease_id is null and new.deleted_at is not null"},
		{"failed", "file_objects", "update", "new.lease_id is null"},
		{"confirmed", "file_quota_usage", "update", "new.kind='organization' and new.reserved_files<old.reserved_files"},
		{"confirmed", "file_quota_usage", "update", "new.kind='session' and new.reserved_files<old.reserved_files"},
		{"confirmed", "file_quota_usage", "update", "new.kind='user' and new.reserved_files<old.reserved_files"},
		{"confirmed", "file_transfers", "update", "new.quota_released_at is not null"},
		{"confirmed", "audit_log", "insert", "new.action='file.quota_released'"},
	} {
		t.Run(fault.operation+"/"+fault.table+"/"+fault.condition, func(t *testing.T) {
			h := newFileFixture(t)
			file, err := h.repository.RegisterUpload(h.ctx, h.actor, h.input)
			if err != nil {
				t.Fatal(err)
			}
			if fault.operation == "expire" {
				h.exec(t, `update files set created_at=clock_timestamp()-interval '2 hours',expires_at=clock_timestamp()-interval '1 hour' where id=$1`, file.ID)
			} else {
				h.expired(t, file.ID)
			}
			var claim files.DeletionClaim
			if fault.operation == "confirmed" || fault.operation == "failed" {
				claim = h.deletion(t)
			}
			h.exec(t, `create function ignore_cleanup_write() returns trigger language plpgsql as $$ begin
			 if `+fault.condition+` then return null;end if;return new;end $$;
			 create trigger ignore_cleanup_write before `+fault.event+` on `+fault.table+` for each row execute function ignore_cleanup_write()`)
			before := fileAdmissionSnapshot(t, h)
			run := func() error {
				switch fault.operation {
				case "expire":
					count, err := h.repository.Expire(h.ctx, 1)
					if err != nil && count != 0 {
						return errors.New("failed expiry returned a success count")
					}
					return err
				case "claim":
					current, err := h.repository.ClaimDeletion(h.ctx)
					if err != nil && current != nil {
						return errors.New("ignored cleanup lease returned authority")
					}
					return err
				default:
					return h.repository.CompleteDeletion(h.ctx, claim, fault.operation == "confirmed")
				}
			}
			if err := run(); !errors.Is(err, files.ErrUnavailable) {
				t.Fatal("missing cleanup evidence reported success", err)
			}
			if fileAdmissionSnapshot(t, h) != before {
				t.Fatal("missing cleanup evidence changed proof or quota")
			}
			h.quota(t, h.input.SizeBytes, 1)
			h.exec(t, `drop trigger ignore_cleanup_write on `+fault.table+`;drop function ignore_cleanup_write()`)
			if err := run(); err != nil {
				t.Fatal("cleanup could not retry restored writes", err)
			}
		})
	}
}

func TestFileCleanupConcurrentClaimAndAcknowledgementReleaseQuotaOnce(t *testing.T) {
	h := newFileFixture(t)
	file, err := h.repository.RegisterUpload(h.ctx, h.actor, h.input)
	if err != nil {
		t.Fatal(err)
	}
	h.expired(t, file.ID)
	claims := make(chan *files.DeletionClaim, 4)
	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			claim, err := h.repository.ClaimDeletion(h.ctx)
			if err != nil {
				t.Error(err)
			}
			claims <- claim
		})
	}
	workers.Wait()
	close(claims)
	var chosen *files.DeletionClaim
	for claim := range claims {
		if claim != nil {
			if chosen != nil {
				t.Fatal("competing cleanup workers claimed the same key")
			}
			chosen = claim
		}
	}
	if chosen == nil {
		t.Fatal("no cleanup worker acquired the available key")
	}
	var accepted atomic.Int32
	for range 4 {
		workers.Go(func() {
			err := h.repository.CompleteDeletion(h.ctx, *chosen, true)
			if err == nil {
				accepted.Add(1)
			} else if !errors.Is(err, files.ErrStale) {
				t.Error(err)
			}
		})
	}
	workers.Wait()
	if accepted.Load() != 1 {
		t.Fatal("duplicate deletion evidence was consumed", accepted.Load())
	}
	h.quota(t, 0, 0)
	var releases int
	if err := h.database.DB.QueryRowContext(h.ctx, `select count(*) from audit_log where action='file.quota_released'`).Scan(&releases); err != nil || releases != 1 {
		t.Fatal("quota release audit duplicated", releases, err)
	}
}
