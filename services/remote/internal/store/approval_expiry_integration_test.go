package store

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

func expiryConsumer(t *testing.T, f *approvalFixture, node string) *ControlConsumer {
	t.Helper()
	c, err := f.database.NewControlConsumer(f.ctx, node)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func expirePendingApprovals(t *testing.T, f *approvalFixture) {
	t.Helper()
	if _, err := f.database.DB.ExecContext(f.ctx, `update approvals set created_at=clock_timestamp()-interval '60 seconds',
	 request_created_at=clock_timestamp()-interval '60 seconds',expires_at=clock_timestamp()-interval '1 second' where metadata_version=1 and state='pending'`); err != nil {
		t.Fatal(err)
	}
}

func TestApprovalExpiryWorkerEndsPendingAndUncertainFactsWithoutNewRegistration(t *testing.T) {
	for _, state := range []string{"pending", "decision_received", "consumed", "settled", "denied"} {
		t.Run(state, func(t *testing.T) {
			f := newApprovalFixture(t)
			metrics := enableApprovalMetrics(t, f)
			c := expiryConsumer(t, f, controlNodeA)
			var deadline time.Time
			if err := f.database.DB.QueryRowContext(f.ctx, `select clock_timestamp()+interval '1 second'`).Scan(&deadline); err != nil {
				t.Fatal(err)
			}
			f.request.ExpiresAt = deadline.UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
			status := f.register(t, f.request)
			if state != "pending" {
				choice := "allow_once"
				if state == "denied" {
					choice = "reject"
				}
				var err error
				status, err = f.control.Decide(f.ctx, f.principal, f.ticket, approvalRaw(t, f.request), f.signed(t, f.request, choice))
				if err != nil {
					t.Fatal(err)
				}
				if state == "consumed" || state == "settled" {
					outcome := ""
					if state == "settled" {
						outcome = "succeeded"
					}
					status, err = f.control.RecordResult(f.ctx, f.connection, 1, resultFor(status, state, outcome))
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			waitForGrantDatabaseExpiry(t, f.ctx, f.database, deadline)
			wantCount, wantState := 1, "expired"
			if state == "decision_received" || state == "consumed" {
				wantState = "outcome_unknown"
			} else if state == "settled" || state == "denied" {
				wantCount, wantState = 0, status.State
			}
			for attempt := range 2 {
				count, err := c.ExpireApprovals(f.ctx, 32)
				if err != nil || count != wantCount {
					t.Fatal("expiry count or retry changed", count, wantCount, err)
				}
				wantCount = 0
				var current, host, outcome string
				if err := f.database.DB.QueryRowContext(f.ctx, `select state,coalesce(host_state,''),coalesce(execution_outcome,'') from approvals where id=$1`, status.ApprovalID).Scan(&current, &host, &outcome); err != nil {
					t.Fatal(err)
				}
				if current != wantState || host != status.HostState || outcome != status.Outcome {
					t.Fatal("expiry invented or changed a Host execution fact", current, host, outcome)
				}
				var events, audits int
				if err := f.database.DB.QueryRowContext(f.ctx, `select (select count(*) from control_outbox where topic='approval.ended'),(select count(*) from audit_log where action='approval.ended')`).Scan(&events, &audits); err != nil {
					t.Fatal(err)
				}
				expected := 1
				if state == "settled" || state == "denied" {
					expected = 0
				}
				if events != expected || audits != expected {
					t.Fatal("expiry events duplicated", attempt, events, audits)
				}
				if got := approvalStateCount(t, metrics, status.State, wantState, "expiry"); got != float64(expected) {
					t.Fatal("expiry metrics did not follow committed transitions", got)
				}
			}
			if state == "consumed" {
				settled, err := f.control.RecordResult(f.ctx, f.connection, 1, resultFor(status, "settled", "succeeded"))
				if err != nil || settled.HostState != "settled" || settled.Outcome != "succeeded" {
					t.Fatal("expiry blocked a later authenticated execution fact", err)
				}
			}
		})
	}
}

func TestApprovalExpiryWorkerIsBoundedConcurrentAndFansOutToEachNode(t *testing.T) {
	f := newApprovalFixture(t)
	a, b := expiryConsumer(t, f, controlNodeA), expiryConsumer(t, f, controlNodeB)
	for range 7 {
		f.register(t, f.freshRequest(t))
	}
	expirePendingApprovals(t, f)
	for _, invalid := range []int{0, 129} {
		if n, err := a.ExpireApprovals(f.ctx, invalid); n != 0 || !errors.Is(err, ErrGrantInvalid) {
			t.Fatal("invalid expiry budget admitted", n, err)
		}
	}
	var callers sync.WaitGroup
	counts := make(chan int, 2)
	for _, c := range []*ControlConsumer{a, b} {
		callers.Go(func() {
			n, err := c.ExpireApprovals(f.ctx, 2)
			if err != nil {
				t.Error(err)
			}
			counts <- n
		})
	}
	callers.Wait()
	close(counts)
	total := 0
	for n := range counts {
		if n < 0 || n > 2 {
			t.Fatal("batch exceeded row budget", n)
		}
		total += n
	}
	for total < 7 {
		n, err := a.ExpireApprovals(f.ctx, 2)
		if err != nil || n < 1 || n > 2 {
			t.Fatal("remaining expiry batch failed", n, err)
		}
		total += n
	}
	assertApprovalCounts(t, f, 7, 7, 0, 7)
	for _, c := range []*ControlConsumer{a, b} {
		events, err := c.PendingControlEvents(f.ctx, 128)
		if err != nil {
			t.Fatal(err)
		}
		ended := 0
		for _, event := range events {
			if event.Topic != "approval.ended" {
				continue
			}
			ended++
			if event.RuntimeID != f.request.RuntimeID || event.ApprovalID == "" {
				t.Fatal("expiry fanout lost scoped identity")
			}
			if err := c.MarkControlEventPublished(f.ctx, event.ID); err != nil {
				t.Fatal(err)
			}
		}
		if ended != 7 {
			t.Fatal("node did not retain its independent expiry delivery", ended)
		}
	}
}

func TestApprovalExpiryWorkerSkipsBusyRowsAndRetainsFutureRequests(t *testing.T) {
	for _, table := range []string{"runtimes", "approvals"} {
		t.Run(table, func(t *testing.T) {
			f := newApprovalFixture(t)
			c := expiryConsumer(t, f, controlNodeA)
			status := f.register(t, f.request)
			if n, err := c.ExpireApprovals(f.ctx, 32); err != nil || n != 0 {
				t.Fatal("future request expired", n, err)
			}
			expirePendingApprovals(t, f)
			gate, err := f.database.DB.BeginTx(f.ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer gate.Rollback()
			id := status.ApprovalID
			if table == "runtimes" {
				id = status.RuntimeID
			}
			if _, err := gate.ExecContext(f.ctx, `select 1 from `+table+` where id=$1 for update`, id); err != nil {
				t.Fatal(err)
			}
			if n, err := c.ExpireApprovals(f.ctx, 32); err != nil || n != 0 {
				t.Fatal("busy row was waited on instead of skipped", n, err)
			}
			if err := gate.Commit(); err != nil {
				t.Fatal(err)
			}
			if n, err := c.ExpireApprovals(f.ctx, 32); err != nil || n != 1 {
				t.Fatal("skipped expiry was lost", n, err)
			}
			assertApprovalCounts(t, f, 1, 1, 0, 1)
		})
	}
}

func TestApprovalExpiryWorkerRollsBackMissingAuditOutboxAndFailedCommit(t *testing.T) {
	for _, failure := range []string{"audit", "outbox", "commit"} {
		t.Run(failure, func(t *testing.T) {
			f := newApprovalFixture(t)
			metrics := enableApprovalMetrics(t, f)
			c := expiryConsumer(t, f, controlNodeA)
			f.register(t, f.request)
			expirePendingApprovals(t, f)
			table, condition := "audit_log", "new.action='approval.ended'"
			if failure == "outbox" {
				table, condition = "control_outbox", "new.topic='approval.ended'"
			}
			body, trigger := `if `+condition+` then return null;end if;return new;`, `create trigger reject_expiry before insert on `+table+` for each row execute function reject_expiry()`
			if failure == "commit" {
				body = `if ` + condition + ` then raise exception 'fixture commit failure';end if;return new;`
				trigger = `create constraint trigger reject_expiry after insert on audit_log deferrable initially deferred for each row execute function reject_expiry()`
			}
			if _, err := f.database.DB.ExecContext(f.ctx, `create function reject_expiry() returns trigger language plpgsql as $$ begin `+body+`end $$;`+trigger); err != nil {
				t.Fatal(err)
			}
			if n, err := c.ExpireApprovals(f.ctx, 32); n != 0 || !errors.Is(err, ErrDatabaseUnavailable) {
				t.Fatal("expiry survived missing durable fact", n, err)
			}
			assertApprovalPending(t, f, f.request)
			assertApprovalCounts(t, f, 1, 1, 0, 0)
			if got := approvalStateCount(t, metrics, "pending", "expired", "expiry"); got != 0 {
				t.Fatal("failed expiry was counted", got)
			}
			if _, err := f.database.DB.ExecContext(f.ctx, `drop trigger reject_expiry on `+table+`;drop function reject_expiry()`); err != nil {
				t.Fatal(err)
			}
			if n, err := c.ExpireApprovals(f.ctx, 32); err != nil || n != 1 {
				t.Fatal("failed expiry could not retry", n, err)
			}
		})
	}
}

func TestApprovalExpiryWorkerRequiresCurrentConsumerAndRecoveryEpoch(t *testing.T) {
	for _, failure := range []string{"generation", "lease", "quarantine", "epoch", "cancelled"} {
		t.Run(failure, func(t *testing.T) {
			f := newApprovalFixture(t)
			c := expiryConsumer(t, f, controlNodeA)
			f.register(t, f.request)
			expirePendingApprovals(t, f)
			ctx := f.ctx
			want := ErrControlConsumerFenced
			query := `update control_consumers set generation=gen_random_uuid()`
			switch failure {
			case "lease":
				query = `update control_consumers set lease_until=clock_timestamp()-interval '1 second'`
			case "quarantine":
				query, want = `with run as (insert into remote_recovery_runs(id,source_epoch,target_epoch,phase,counts)
				 values(gen_random_uuid(),remote_database_epoch(),gen_random_uuid(),'quarantined','{}') returning id)
				 update remote_recovery_state set phase='quarantined',recovery_id=(select id from run)`, ErrRecoveryUnavailable
			case "epoch":
				c.databaseEpoch, want, query = approvalTestUUID(t), ErrRecoveryUnavailable, ""
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want, query = ErrDatabaseUnavailable, ""
			}
			if query != "" {
				if _, err := f.database.DB.ExecContext(f.ctx, query); err != nil {
					t.Fatal(err)
				}
			}
			if n, err := c.ExpireApprovals(ctx, 32); n != 0 || !errors.Is(err, want) {
				t.Fatal("stale maintenance authority expired rows", n, err)
			}
			assertApprovalPending(t, f, f.request)
			assertApprovalCounts(t, f, 1, 1, 0, 0)
		})
	}
}

func TestApprovalExpiryWorkerRechecksConsumerLeaseAfterAuditWait(t *testing.T) {
	f := newApprovalFixture(t)
	c := expiryConsumer(t, f, controlNodeA)
	f.register(t, f.request)
	expirePendingApprovals(t, f)
	gate, fragment := holdApprovalExpiryWrite(t, f, "audit", "approval.ended")
	var deadline time.Time
	if err := f.database.DB.QueryRowContext(f.ctx, `update control_consumers set lease_until=clock_timestamp()+interval '400 milliseconds' returning lease_until`).Scan(&deadline); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { _, err := c.ExpireApprovals(f.ctx, 32); result <- err }()
	waitForGrantLock(t, f.ctx, f.database, fragment)
	waitForGrantDatabaseExpiry(t, f.ctx, f.database, deadline)
	if err := gate.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, ErrControlConsumerFenced) {
		t.Fatal("expired maintenance lease committed changes", err)
	}
	assertApprovalPending(t, f, f.request)
	assertApprovalCounts(t, f, 1, 1, 0, 0)
}

func TestApprovalExpiryWorkerAuditWaitDoesNotBlockRenewalAndFencesNewGeneration(t *testing.T) {
	for _, replacement := range []bool{false, true} {
		name := "renewal"
		if replacement {
			name = "generation"
		}
		t.Run(name, func(t *testing.T) {
			f := newApprovalFixture(t)
			c := expiryConsumer(t, f, controlNodeA)
			f.register(t, f.request)
			expirePendingApprovals(t, f)
			gate, fragment := holdApprovalExpiryWrite(t, f, "audit", "approval.ended")
			result := make(chan error, 1)
			go func() { _, err := c.ExpireApprovals(f.ctx, 32); result <- err }()
			waitForGrantLock(t, f.ctx, f.database, fragment)
			renewal, cancel := context.WithTimeout(f.ctx, 300*time.Millisecond)
			defer cancel()
			if err := c.Renew(renewal); err != nil {
				t.Fatal("blocked expiry delayed independent consumer renewal", err)
			}
			if _, err := c.PendingControlEvents(renewal, 128); err != nil {
				t.Fatal("blocked expiry delayed independent outbox poll", err)
			}
			if replacement {
				if _, err := f.database.DB.ExecContext(renewal, `update control_consumers set generation=gen_random_uuid()`); err != nil {
					t.Fatal("expiry pinned consumer generation during audit wait", err)
				}
			}
			if err := gate.Commit(); err != nil {
				t.Fatal(err)
			}
			err := <-result
			if replacement {
				if !errors.Is(err, ErrControlConsumerFenced) {
					t.Fatal("replaced generation committed expired metadata", err)
				}
				assertApprovalPending(t, f, f.request)
				assertApprovalCounts(t, f, 1, 1, 0, 0)
			} else {
				if err != nil {
					t.Fatal("renewal invalidated a current expiry batch", err)
				}
				assertApprovalCounts(t, f, 1, 1, 0, 1)
			}
		})
	}
}

func TestApprovalExpiryWorkerHonorsEarlierDecisionDeadlineAndKeepsEvidence(t *testing.T) {
	f := newApprovalFixture(t)
	c := expiryConsumer(t, f, controlNodeA)
	f.register(t, f.request)
	deadline := approvalExpiryDeadline(t, f)
	compact := signApprovalExpiryDecision(t, f, "allow_once", time.Now().UTC().Truncate(time.Millisecond), deadline)
	status, err := f.control.Decide(f.ctx, f.principal, f.ticket, approvalRaw(t, f.request), compact)
	if err != nil {
		t.Fatal(err)
	}
	waitForGrantDatabaseExpiry(t, f.ctx, f.database, deadline)
	if n, err := c.ExpireApprovals(f.ctx, 32); err != nil || n != 1 {
		t.Fatal("decision deadline did not end the longer request", n, err)
	}
	var state, retained, fingerprint string
	var evidence, material int
	if err := f.database.DB.QueryRowContext(f.ctx, `select a.state,a.decision_jws,f.jws_sha256,
	 (select count(*) from approval_decision_evidence),(select count(*) from approval_decision_evidence_material)
	 from approvals a join approval_evidence_fingerprints f on f.approval_id=a.id where a.id=$1`, status.ApprovalID).Scan(&state, &retained, &fingerprint, &evidence, &material); err != nil {
		t.Fatal(err)
	}
	var intact bool
	if err := f.database.DB.QueryRowContext(f.ctx, `select $1=encode(sha256(convert_to($2,'UTF8')),'hex')`, fingerprint, compact).Scan(&intact); err != nil {
		t.Fatal(err)
	}
	if state != "outcome_unknown" || retained != compact || !intact || evidence != 1 || material != 1 {
		t.Fatal("expiry destroyed or rewrote retained decision evidence")
	}
}

func TestApprovalExpiryWorkerCleansOfflineRetiredRuntimeMetadata(t *testing.T) {
	f := newApprovalFixture(t)
	c := expiryConsumer(t, f, controlNodeA)
	f.register(t, f.request)
	expirePendingApprovals(t, f)
	if _, err := f.database.DB.ExecContext(f.ctx, `update runtimes set revoked_at=clock_timestamp(),last_seen_at=clock_timestamp()-interval '1 hour'`); err != nil {
		t.Fatal(err)
	}
	if n, err := c.ExpireApprovals(f.ctx, 32); err != nil || n != 1 {
		t.Fatal("offline runtime left pending forever", n, err)
	}
	assertApprovalCounts(t, f, 1, 1, 0, 1)
}

func TestApprovalExpiryWorkerMigrationRetainsTombstonesAndLegacyRows(t *testing.T) {
	f := newApprovalFixture(t)
	c := expiryConsumer(t, f, controlNodeA)
	f.register(t, f.request)
	var legacy string
	if err := f.database.DB.QueryRowContext(f.ctx, `insert into approvals(id,session_id,runtime_epoch,execution_id,
	 binding_sha256,policy_version,state,expires_at,created_at,runtime_id)
	 select gen_random_uuid(),session_id,runtime_epoch,gen_random_uuid(),binding_sha256,policy_version,'pending',
	 clock_timestamp()-interval '1 second',clock_timestamp()-interval '60 seconds',runtime_id from approvals where id=$1 returning id::text`, f.request.ApprovalID).Scan(&legacy); err != nil {
		t.Fatal(err)
	}
	expirePendingApprovals(t, f)
	if n, err := c.ExpireApprovals(f.ctx, 32); err != nil || n != 1 {
		t.Fatal("legacy row was reinterpreted", n, err)
	}
	for _, direction := range []string{"down", "up"} {
		raw, err := os.ReadFile("../../../../deploy/sql/044_approval_expiry." + direction + ".sql")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.database.DB.ExecContext(f.ctx, string(raw)); err != nil {
			t.Fatal("expiry index migration failed", direction, err)
		}
		assertApprovalCounts(t, f, 2, 1, 0, 1)
	}
	var state string
	if err := f.database.DB.QueryRowContext(f.ctx, `select state from approvals where id=$1`, legacy).Scan(&state); err != nil || state != "pending" {
		t.Fatal("legacy pending row was revived or reclassified", state, err)
	}
	if n, err := c.ExpireApprovals(f.ctx, 32); err != nil || n != 0 {
		t.Fatal("migration replayed an expiry transition", n, err)
	}
}
