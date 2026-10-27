package store

import (
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/approval"
	"dsh-mobile-ustc/services/remote/internal/observability"
)

func approvalStateCount(t *testing.T, metrics *observability.Metrics, from, to, cause string) float64 {
	t.Helper()
	value, _ := commandMetric(t, metrics, "approval_state_transitions_total", map[string]string{"from": from, "to": to, "cause": cause})
	return value
}
func approvalHostCount(t *testing.T, metrics *observability.Metrics, from, to, outcome string) float64 {
	t.Helper()
	value, _ := commandMetric(t, metrics, "approval_host_transitions_total", map[string]string{"from": from, "to": to, "outcome": outcome})
	return value
}
func enableApprovalMetrics(t *testing.T, fixture *approvalFixture) *observability.Metrics {
	t.Helper()
	metrics := observability.New()
	if err := fixture.database.ConfigureApprovalMetrics(metrics); err != nil {
		t.Fatal(err)
	}
	return metrics
}

func TestApprovalMetricsSeparateDecisionConsumptionAndExecutionUnderRetries(t *testing.T) {
	f := newApprovalFixture(t)
	metrics := enableApprovalMetrics(t, f)
	if err := f.database.ConfigureApprovalMetrics(observability.New()); !errors.Is(err, ErrDatabaseConfig) {
		t.Fatal("live approval observer was replaced")
	}
	var callers sync.WaitGroup
	for range 4 {
		callers.Go(func() {
			if _, err := f.control.Register(f.ctx, f.connection, 1, approvalRaw(t, f.request)); err != nil {
				t.Error(err)
			}
		})
	}
	callers.Wait()
	if got := approvalStateCount(t, metrics, "none", "pending", "registration"); got != 1 {
		t.Fatal("registration retry counted twice", got)
	}
	raw := approvalRaw(t, f.request)
	decision := f.signed(t, f.request, "allow_once")
	for range 4 {
		callers.Go(func() {
			if _, err := f.control.Decide(f.ctx, f.principal, f.ticket, raw, decision); err != nil {
				t.Error(err)
			}
		})
	}
	callers.Wait()
	if got := approvalStateCount(t, metrics, "pending", "decision_received", "decision"); got != 1 {
		t.Fatal("decision retry counted twice", got)
	}
	if got := approvalHostCount(t, metrics, "consumed", "settled", "succeeded"); got != 0 {
		t.Fatal("allow decision was counted as execution")
	}
	provider, signer := newTestLeaseProvider(t, f, time.Now().Add(time.Hour))
	ids := map[string]bool{}
	for range 2 {
		compact, err := provider.Issue(f.ctx, f.connection, 1, raw)
		if err != nil {
			t.Fatal(err)
		}
		verified, err := approval.VerifyAuthorization(compact, signer.Authority(), raw, decision, f.connection.ConnectionID, time.Now())
		if err != nil || ids[verified.Lease.LeaseID] {
			t.Fatal("renewal did not create its own valid bounded lease", err)
		}
		ids[verified.Lease.LeaseID] = true
	}
	if count, _ := commandMetric(t, metrics, "approval_lease_preparations_total", map[string]string{"decision": "allow_once"}); count != 2 {
		t.Fatal("distinct lease preparation was lost", count)
	}
	if count, sum := commandMetric(t, metrics, "approval_lease_lifetime_seconds", map[string]string{"decision": "allow_once"}); count != 2 || sum <= 0 || sum > 6 {
		t.Fatal("lease lifetime escaped three-second bound", count, sum)
	}
	status, _, err := func() (ApprovalStatus, string, error) {
		tx, err := f.database.DB.BeginTx(f.ctx, nil)
		if err != nil {
			return ApprovalStatus{}, "", err
		}
		defer tx.Rollback()
		return readApproval(f.ctx, tx, f.request.ApprovalID)
	}()
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"approved", "consumed", "settled"} {
		outcome := ""
		if state == "settled" {
			outcome = "succeeded"
		}
		result := resultFor(status, state, outcome)
		for range 2 {
			status, err = f.control.RecordResult(f.ctx, f.connection, 1, result)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if got := approvalStateCount(t, metrics, "decision_received", "allowed", "host_result"); got != 1 {
		t.Fatal("consumption and settlement duplicated control allowed state", got)
	}
	for _, edge := range [][3]string{{"none", "approved", "none"}, {"approved", "consumed", "none"}, {"consumed", "settled", "succeeded"}} {
		if got := approvalHostCount(t, metrics, edge[0], edge[1], edge[2]); got != 1 {
			t.Fatal("Host fact repeated or missing", edge, got)
		}
	}
	for _, operation := range []string{"register", "decide", "host_result", "lease"} {
		if count, _ := commandMetric(t, metrics, "approval_operation_duration_seconds", map[string]string{"operation": operation, "result": "ok"}); count == 0 {
			t.Fatal("approval attempt timing absent", operation)
		}
	}
	w := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	for _, private := range []string{f.request.ApprovalID, f.request.RuntimeID, f.ticket.DeviceID, f.ticket.UserID, f.request.CallID, string(f.request.Arguments), decision, signer.Authority().KeyID} {
		if strings.Contains(w.Body.String(), private) {
			t.Fatal("approval metric exposed identity, context or proof")
		}
	}
}

func TestApprovalMetricsLifecycleSideEffectsObserveOnlySuccessfulOuterCommit(t *testing.T) {
	f := newApprovalFixture(t)
	metrics := enableApprovalMetrics(t, f)
	expired, keep := f.request, f.freshRequest(t)
	f.register(t, expired)
	f.register(t, keep)
	expire := func(id string) {
		t.Helper()
		if _, err := f.database.DB.ExecContext(f.ctx, `update approvals set created_at=clock_timestamp()-interval '60 seconds',request_created_at=clock_timestamp()-interval '60 seconds',expires_at=clock_timestamp()-interval '1 second' where id=$1`, id); err != nil {
			t.Fatal(err)
		}
	}
	expire(expired.ApprovalID)
	f.register(t, keep) // an unchanged registration can still commit expiry of another row
	if got := approvalStateCount(t, metrics, "pending", "expired", "expiry"); got != 1 {
		t.Fatal("expiry on duplicate registration was lost", got)
	}
	f.register(t, keep)
	if got := approvalStateCount(t, metrics, "pending", "expired", "expiry"); got != 1 {
		t.Fatal("expiry repeated without state change", got)
	}
	third, next := f.freshRequest(t), f.freshRequest(t)
	f.register(t, third)
	expire(third.ApprovalID)
	if _, err := f.database.DB.ExecContext(f.ctx, `create function fixture_approval_commit_failure() returns trigger language plpgsql as $$ begin if new.action='approval.pending' then raise exception 'fixture deferred approval failure';end if;return null;end $$;create constraint trigger fixture_approval_commit_failure after insert on audit_log deferrable initially deferred for each row execute function fixture_approval_commit_failure()`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.control.Register(f.ctx, f.connection, 1, approvalRaw(t, next)); !errors.Is(err, ErrDatabaseUnavailable) {
		t.Fatal("deferred registration failure did not roll back", err)
	}
	if got := approvalStateCount(t, metrics, "pending", "expired", "expiry"); got != 1 {
		t.Fatal("rolled-back expiry was counted", got)
	}
	if got := approvalStateCount(t, metrics, "none", "pending", "registration"); got != 3 {
		t.Fatal("failed creation was counted", got)
	}
	if _, err := f.database.DB.ExecContext(f.ctx, `drop trigger fixture_approval_commit_failure on audit_log;drop function fixture_approval_commit_failure()`); err != nil {
		t.Fatal(err)
	}
	f.register(t, next)
	if got := approvalStateCount(t, metrics, "pending", "expired", "expiry"); got != 2 {
		t.Fatal("committed expiry absent", got)
	}
	if err := f.database.DetachRuntimeConnection(f.ctx, f.connection.InstallationID, f.connection.RuntimeID, f.connection.RuntimeEpoch, f.connection.ConnectionID); err != nil {
		t.Fatal(err)
	}
	if got := approvalStateCount(t, metrics, "pending", "invalidated", "connection"); got != 2 {
		t.Fatal("disconnect lifecycle count incorrect", got)
	}
	if err := f.database.DetachRuntimeConnection(f.ctx, f.connection.InstallationID, f.connection.RuntimeID, f.connection.RuntimeEpoch, f.connection.ConnectionID); err != nil {
		t.Fatal(err)
	}
	if got := approvalStateCount(t, metrics, "pending", "invalidated", "connection"); got != 2 {
		t.Fatal("stale disconnect repeated transitions", got)
	}
}

func TestApprovalMetricsDeniedChoiceAndFailedLeaseCommitDoNotImplyDelivery(t *testing.T) {
	t.Run("decision_and_execution_commit", func(t *testing.T) {
		f := newApprovalFixture(t)
		metrics := enableApprovalMetrics(t, f)
		f.register(t, f.request)
		if _, err := f.database.DB.ExecContext(f.ctx, `create function fixture_approval_commit_failure() returns trigger language plpgsql as $$ begin if new.action='approval.decided' or new.action='approval.result' then raise exception 'fixture deferred approval failure';end if;return null;end $$;create constraint trigger fixture_approval_commit_failure after insert on audit_log deferrable initially deferred for each row execute function fixture_approval_commit_failure()`); err != nil {
			t.Fatal(err)
		}
		if _, err := f.control.Decide(f.ctx, f.principal, f.ticket, approvalRaw(t, f.request), f.signed(t, f.request, "allow_once")); !errors.Is(err, ErrDatabaseUnavailable) {
			t.Fatal("decision commit did not fail", err)
		}
		if approvalStateCount(t, metrics, "pending", "decision_received", "decision") != 0 {
			t.Fatal("rolled-back decision counted")
		}
		if _, err := f.database.DB.ExecContext(f.ctx, `alter table audit_log disable trigger fixture_approval_commit_failure`); err != nil {
			t.Fatal(err)
		}
		status, err := f.control.Decide(f.ctx, f.principal, f.ticket, approvalRaw(t, f.request), f.signed(t, f.request, "allow_once"))
		if err != nil {
			t.Fatal(err)
		}
		for _, state := range []string{"approved", "consumed"} {
			status, err = f.control.RecordResult(f.ctx, f.connection, 1, resultFor(status, state, ""))
			if err != nil {
				t.Fatal(err)
			}
		}
		if _, err := f.database.DB.ExecContext(f.ctx, `alter table audit_log enable trigger fixture_approval_commit_failure`); err != nil {
			t.Fatal(err)
		}
		if _, err := f.control.RecordResult(f.ctx, f.connection, 1, resultFor(status, "settled", "succeeded")); !errors.Is(err, ErrDatabaseUnavailable) {
			t.Fatal("execution fact commit did not fail", err)
		}
		if approvalHostCount(t, metrics, "consumed", "settled", "succeeded") != 0 {
			t.Fatal("uncommitted execution success counted")
		}
	})
	t.Run("reject", func(t *testing.T) {
		f := newApprovalFixture(t)
		metrics := enableApprovalMetrics(t, f)
		status := acceptResultFixture(t, f, "reject")
		for range 2 {
			if _, err := f.control.RecordResult(f.ctx, f.connection, 1, resultFor(status, "denied", "")); err != nil {
				t.Fatal(err)
			}
		}
		if approvalStateCount(t, metrics, "pending", "denied", "decision") != 1 || approvalHostCount(t, metrics, "none", "denied", "none") != 1 {
			t.Fatal("deny choice and Host deny were conflated")
		}
		provider, _ := newTestLeaseProvider(t, f, time.Now().Add(time.Hour))
		if _, err := provider.Issue(f.ctx, f.connection, 1, approvalRaw(t, f.request)); err != nil {
			t.Fatal(err)
		}
		if count, _ := commandMetric(t, metrics, "approval_lease_preparations_total", map[string]string{"decision": "reject"}); count != 1 {
			t.Fatal("negative authority delivery mislabeled")
		}
		if approvalHostCount(t, metrics, "consumed", "settled", "succeeded") != 0 {
			t.Fatal("reject preparation counted execution")
		}
	})
	t.Run("failed_commit", func(t *testing.T) {
		f := newApprovalFixture(t)
		metrics := enableApprovalMetrics(t, f)
		acceptResultFixture(t, f, "allow_once")
		provider, _ := newTestLeaseProvider(t, f, time.Now().Add(time.Hour))
		if _, err := f.database.DB.ExecContext(f.ctx, `create function fixture_lease_commit_failure() returns trigger language plpgsql as $$ begin if new.action='approval.authorization.prepare' then raise exception 'fixture deferred lease failure';end if;return null;end $$;create constraint trigger fixture_lease_commit_failure after insert on audit_log deferrable initially deferred for each row execute function fixture_lease_commit_failure()`); err != nil {
			t.Fatal(err)
		}
		if compact, err := provider.Issue(f.ctx, f.connection, 1, approvalRaw(t, f.request)); !errors.Is(err, ErrDatabaseUnavailable) || compact != "" {
			t.Fatal("failed commit returned lease", err)
		}
		if count, _ := commandMetric(t, metrics, "approval_lease_preparations_total", map[string]string{"decision": "allow_once"}); count != 0 {
			t.Fatal("failed lease preparation counted", count)
		}
	})
	t.Run("expired_after_commit", func(t *testing.T) {
		f := newApprovalFixture(t)
		metrics := enableApprovalMetrics(t, f)
		acceptResultFixture(t, f, "allow_once")
		provider, _ := newTestLeaseProvider(t, f, time.Now().Add(time.Hour))
		if _, err := f.database.DB.ExecContext(f.ctx, `update runtime_grants set expires_at=clock_timestamp()+interval '300 milliseconds'`); err != nil {
			t.Fatal(err)
		}
		if _, err := f.database.DB.ExecContext(f.ctx, `create function fixture_lease_commit_delay() returns trigger language plpgsql as $$ begin if new.action='approval.authorization.prepare' then perform pg_sleep(0.4);end if;return null;end $$;create constraint trigger fixture_lease_commit_delay after insert on audit_log deferrable initially deferred for each row execute function fixture_lease_commit_delay()`); err != nil {
			t.Fatal(err)
		}
		if compact, err := provider.Issue(f.ctx, f.connection, 1, approvalRaw(t, f.request)); !errors.Is(err, ErrApprovalExpired) || compact != "" {
			t.Fatal("post-commit expiry returned proof", err)
		}
		if count, _ := commandMetric(t, metrics, "approval_lease_preparations_total", map[string]string{"decision": "allow_once"}); count != 1 {
			t.Fatal("confirmed preparation disappeared")
		}
		if count, _ := commandMetric(t, metrics, "approval_lease_availability_checks_total", map[string]string{"decision": "allow_once", "result": "expired"}); count != 1 {
			t.Fatal("expired preparation looked available")
		}
	})
}

func TestApprovalMetricsConnectionReplacementKeepsUncertaintyAndHistoricalSettlementDistinct(t *testing.T) {
	f := newApprovalFixture(t)
	metrics := enableApprovalMetrics(t, f)
	status := acceptResultFixture(t, f, "allow_once")
	var err error
	status, err = f.control.RecordResult(f.ctx, f.connection, 1, resultFor(status, "approved", ""))
	if err != nil {
		t.Fatal(err)
	}
	old := f.connection
	replacement, err := f.database.AttachRuntimeConnection(f.ctx, RuntimeConnectionInput{InstallationID: old.InstallationID, KeyVersion: 1, RuntimeID: old.RuntimeID, RuntimeEpoch: approvalTestUUID(t), ConnectionID: approvalTestUUID(t), DSHVersion: "0.2.1-rc.2", ApplicationVersion: "approval-metrics-fixture", PluginVersion: "test", ProtocolVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	if got := approvalStateCount(t, metrics, "decision_received", "outcome_unknown", "connection"); got != 1 {
		t.Fatal("replacement uncertainty was lost", got)
	}
	if approvalHostCount(t, metrics, "approved", "settled", "succeeded") != 0 {
		t.Fatal("replacement invented execution result")
	}
	for range 2 {
		if _, err := f.control.RecordResult(f.ctx, replacement, 1, resultFor(status, "settled", "succeeded")); err != nil {
			t.Fatal(err)
		}
	}
	if approvalStateCount(t, metrics, "outcome_unknown", "allowed", "host_result") != 1 || approvalHostCount(t, metrics, "approved", "settled", "succeeded") != 1 {
		t.Fatal("historical correction duplicated or lost")
	}
	provider, _ := newTestLeaseProvider(t, f, time.Now().Add(time.Hour))
	if compact, err := provider.Issue(f.ctx, replacement, 1, approvalRaw(t, f.request)); err == nil || compact != "" {
		t.Fatal("historical settlement acquired new execution authority")
	}
}
