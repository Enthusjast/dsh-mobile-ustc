package store

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/files"
)

const fileTestPolicy = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func (fixture *fileFixture) scanning(t *testing.T) files.Record {
	t.Helper()
	file, err := fixture.repository.RegisterUpload(fixture.ctx, fixture.actor, fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	file, err = fixture.repository.BeginScan(fixture.ctx, fixture.actor, file.ID)
	if err != nil {
		t.Fatal(err)
	}
	return file
}
func (fixture *fileFixture) claim(t *testing.T) files.ScanClaim {
	t.Helper()
	claim, err := fixture.repository.ClaimScan(fixture.ctx, fileTestPolicy)
	if err != nil || claim == nil {
		t.Fatalf("scan claim=%v error=%v", claim, err)
	}
	return *claim
}

func TestPostgresOneFileScanLeaseAndAtomicCleanEvidence(t *testing.T) {
	h := newFileFixture(t)
	file := h.scanning(t)
	const workers = 8
	claims := make(chan *files.ScanClaim, workers)
	failures := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			claim, err := h.repository.ClaimScan(h.ctx, fileTestPolicy)
			claims <- claim
			failures <- err
		}()
	}
	wait.Wait()
	close(claims)
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatalf("competing scan=%v", err)
		}
	}
	var chosen *files.ScanClaim
	count := 0
	for claim := range claims {
		if claim != nil {
			chosen = claim
			count++
		}
	}
	if count != 1 || chosen.File.ID != file.ID {
		t.Fatalf("active claims=%d", count)
	}
	until, err := h.repository.RenewScan(h.ctx, *chosen)
	if err != nil || until.Before(chosen.LeaseUntil) {
		t.Fatalf("renew=%v %v", until, err)
	}
	wrong := *chosen
	wrong.LeaseID = approvalTestUUID(t)
	if err := h.repository.CompleteScan(h.ctx, wrong); !errors.Is(err, files.ErrStale) {
		t.Fatalf("wrong lease=%v", err)
	}
	wrong = *chosen
	wrong.PolicySHA256 = strings.Repeat("b", 64)
	if _, err := h.repository.RenewScan(h.ctx, wrong); !errors.Is(err, files.ErrStale) {
		t.Fatalf("wrong policy=%v", err)
	}
	// This repository test supplies the trusted worker's completion fact. The
	// file service separately verifies bytes/scanner/S3 before calling it.
	for range 2 {
		if err := h.repository.CompleteScan(h.ctx, *chosen); err != nil {
			t.Fatal(err)
		}
	}
	state, err := h.repository.Status(h.ctx, h.actor, file.ID)
	if err != nil || state.State != "clean" || state.CommittedAttempt != chosen.AttemptID || !state.ExpiresAt.After(file.ExpiresAt) {
		t.Fatalf("clean state=%+v error=%v", state, err)
	}
	var eventCount, auditCount int
	var object, policy string
	if err := h.database.DB.QueryRowContext(h.ctx, `select f.object_key,t.scanner_policy_sha256,(select count(*) from control_outbox where topic='file.clean'),(select count(*) from audit_log where action='file.scan_clean') from files f join file_transfers t on t.file_id=f.id where f.id=$1`, file.ID).Scan(&object, &policy, &eventCount, &auditCount); err != nil {
		t.Fatal(err)
	}
	key, _ := chosen.Key()
	if object != key.StorageKey() || policy != fileTestPolicy || eventCount != 1 || auditCount != 1 {
		t.Fatal("clean metadata, candidate and outbox diverged")
	}
	if _, err := h.repository.ClaimScan(h.ctx, fileTestPolicy); err != nil {
		t.Fatal(err)
	}
	if err := h.repository.FailScan(h.ctx, *chosen, "content_rejected", false); !errors.Is(err, files.ErrStale) {
		t.Fatal("completed scan was reversed")
	}
}

func TestPostgresExpiredScanWorkerCannotRenewOrPublishAfterTakeover(t *testing.T) {
	h := newFileFixture(t)
	h.scanning(t)
	old := h.claim(t)
	h.exec(t, `update file_scan_attempts set lease_until=clock_timestamp()-interval '1 second' where id=$1`, old.AttemptID)
	if _, err := h.repository.RenewScan(h.ctx, old); !errors.Is(err, files.ErrStale) {
		t.Fatalf("expired renewal=%v", err)
	}
	if err := h.repository.CompleteScan(h.ctx, old); !errors.Is(err, files.ErrStale) {
		t.Fatalf("expired completion=%v", err)
	}
	fresh := h.claim(t)
	if fresh.AttemptID == old.AttemptID || fresh.LeaseID == old.LeaseID {
		t.Fatal("takeover reused the old candidate or lease")
	}
	if err := h.repository.CompleteScan(h.ctx, old); !errors.Is(err, files.ErrStale) {
		t.Fatal("abandoned worker published after takeover")
	}
	if err := h.repository.CompleteScan(h.ctx, fresh); err != nil {
		t.Fatal(err)
	}
	var abandoned, tracked int
	if err := h.database.DB.QueryRowContext(h.ctx, `select (select count(*) from file_scan_attempts where state='abandoned'),(select count(*) from file_objects)`).Scan(&abandoned, &tracked); err != nil || abandoned != 1 || tracked != 3 {
		t.Fatalf("tracked=%d abandoned=%d error=%v", tracked, abandoned, err)
	}
}

func TestPostgresScanRevocationAndAuditFailureCannotProduceClean(t *testing.T) {
	t.Run("revoked", func(t *testing.T) {
		h := newFileFixture(t)
		file := h.scanning(t)
		claim := h.claim(t)
		h.exec(t, `update runtime_grants set grant_version=grant_version+1`)
		if _, err := h.repository.RenewScan(h.ctx, claim); !errors.Is(err, files.ErrAccess) {
			t.Fatalf("revoked renewal=%v", err)
		}
		if err := h.repository.CompleteScan(h.ctx, claim); !errors.Is(err, files.ErrAccess) {
			t.Fatalf("revoked completion=%v", err)
		}
		if err := h.repository.FailScan(h.ctx, claim, "access_revoked", false); err != nil {
			t.Fatal(err)
		}
		status, err := h.repository.Status(h.ctx, h.actor, file.ID)
		if err != nil || status.State != "rejected" || status.ErrorCode != "access_revoked" {
			t.Fatalf("revoked status=%+v error=%v", status, err)
		}
	})
	t.Run("audit", func(t *testing.T) {
		h := newFileFixture(t)
		file := h.scanning(t)
		claim := h.claim(t)
		h.exec(t, `create function fail_file_clean_audit() returns trigger language plpgsql as $$ begin raise exception 'injected clean audit failure'; end $$;
		 create trigger file_clean_audit_failure before insert on audit_log for each row when(new.action='file.scan_clean') execute function fail_file_clean_audit()`)
		if err := h.repository.CompleteScan(h.ctx, claim); !errors.Is(err, files.ErrUnavailable) {
			t.Fatalf("audit failure=%v", err)
		}
		var fileState, attemptState string
		var events int
		if err := h.database.DB.QueryRowContext(h.ctx, `select f.state,a.state,(select count(*) from control_outbox where topic='file.clean') from files f join file_scan_attempts a on a.file_id=f.id where f.id=$1`, file.ID).Scan(&fileState, &attemptState, &events); err != nil || fileState != "scanning" || attemptState != "active" || events != 0 {
			t.Fatalf("partial clean=%s/%s/%d error=%v", fileState, attemptState, events, err)
		}
		h.exec(t, `drop trigger file_clean_audit_failure on audit_log;drop function fail_file_clean_audit()`)
		if err := h.repository.CompleteScan(h.ctx, claim); err != nil {
			t.Fatal(err)
		}
	})
}

func TestPostgresScanRetriesHaveFreshKeysBoundedBudgetAndNoLostCleanupKeys(t *testing.T) {
	h := newFileFixture(t)
	file := h.scanning(t)
	for attempt := 1; attempt <= fileScanMaxAttempts; attempt++ {
		claim := h.claim(t)
		if err := h.repository.FailScan(h.ctx, claim, "scan_unavailable", true); err != nil {
			t.Fatal(err)
		}
		status, err := h.repository.Status(h.ctx, h.actor, file.ID)
		if err != nil {
			t.Fatal(err)
		}
		want := "scanning"
		if attempt == fileScanMaxAttempts {
			want = "rejected"
		}
		if status.State != want || status.ErrorCode != "scan_unavailable" {
			t.Fatalf("retry %d state=%+v", attempt, status)
		}
		h.exec(t, `update file_transfers set scan_ready_at=clock_timestamp() where file_id=$1`, file.ID)
	}
	if next, err := h.repository.ClaimScan(h.ctx, fileTestPolicy); err != nil || next != nil {
		t.Fatal("exhausted file reentered scan")
	}
	var objects int
	if err := h.database.DB.QueryRowContext(h.ctx, `select count(*) from file_objects`).Scan(&objects); err != nil || objects != 4 {
		t.Fatal("scan attempts lost their cleanup keys")
	}
}

func TestPostgresQueuedFileRechecksAuthorityBeforeStartingScan(t *testing.T) {
	h := newFileFixture(t)
	file := h.scanning(t)
	h.exec(t, `update devices set revoked_at=clock_timestamp() where id=$1`, h.actor.DeviceID)
	if claim, err := h.repository.ClaimScan(h.ctx, fileTestPolicy); err != nil || claim != nil {
		t.Fatal("revoked queued file started a scan")
	}
	var state, code string
	if err := h.database.DB.QueryRowContext(h.ctx, `select f.state,t.error_code from files f join file_transfers t on t.file_id=f.id where f.id=$1`, file.ID).Scan(&state, &code); err != nil || state != "rejected" || code != "access_revoked" {
		t.Fatalf("queued revoke=%s/%s error=%v", state, code, err)
	}
}

func TestPostgresScanLeaseIsRecheckedAfterWaitingOnAuthorization(t *testing.T) {
	h := newFileFixture(t)
	h.scanning(t)
	claim := h.claim(t)
	h.exec(t, `update file_scan_attempts set lease_until=clock_timestamp()+interval '500 milliseconds' where id=$1`, claim.AttemptID)
	blocking, err := h.database.DB.BeginTx(h.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer blocking.Rollback()
	if _, err := blocking.ExecContext(h.ctx, `select grant_version from runtime_grants for update`); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- h.repository.CompleteScan(h.ctx, claim) }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		var waiting int
		if err := h.database.DB.QueryRowContext(h.ctx, `select count(*) from pg_stat_activity where datname=current_database() and wait_event_type='Lock' and query like '%for share of u,d,m,h,i,r,g,s%'`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("completion did not wait on authority")
		}
		time.Sleep(5 * time.Millisecond)
	}
	for {
		var expired bool
		if err := h.database.DB.QueryRowContext(h.ctx, `select lease_until<clock_timestamp() from file_scan_attempts where id=$1`, claim.AttemptID).Scan(&expired); err != nil {
			t.Fatal(err)
		}
		if expired {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := blocking.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, files.ErrStale) {
		t.Fatalf("expired completion after authority wait=%v", err)
	}
}
