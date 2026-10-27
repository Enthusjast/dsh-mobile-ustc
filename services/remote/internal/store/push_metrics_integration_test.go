package store

import (
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/observability"
	"dsh-mobile-ustc/services/remote/internal/push"
)

func (h *pushFixture) exec(t *testing.T, query string, args ...any) {
	t.Helper()
	if _, err := h.database.DB.ExecContext(h.ctx, query, args...); err != nil {
		t.Fatal(err)
	}
}

func pushDeliveryCount(t *testing.T, metrics *observability.Metrics, kind, state, code string) float64 {
	t.Helper()
	count, _ := commandMetric(t, metrics, "push_delivery_results_total", map[string]string{"kind": kind, "state": state, "code": code})
	return count
}

func TestPushMetricsSeparateCommittedDeliveryAndDeduplicatedClientReports(t *testing.T) {
	h := newPushFixture(t)
	input, revokeSecret := h.active(t)
	metrics := observability.New()
	if err := h.database.ConfigurePushMetrics(metrics); err != nil {
		t.Fatal(err)
	}
	if err := h.database.ConfigurePushMetrics(observability.New()); !errors.Is(err, ErrDatabaseConfig) {
		t.Fatal("live push observer replaced")
	}
	if _, err := h.control.Register(h.ctx, h.connection, 1, approvalRaw(t, h.request)); err != nil {
		t.Fatal(err)
	}
	if err := h.push.Plan(h.ctx); err != nil {
		t.Fatal(err)
	}
	claim, err := h.push.Claim(h.ctx)
	if err != nil || claim == nil {
		t.Fatal("notification was not claimed", err)
	}
	h.exec(t, `create table fixture_push_commit_failure(action text);
	create function fixture_push_commit_failure() returns trigger language plpgsql as $$ begin
	if exists(select 1 from fixture_push_commit_failure where action=new.action) then raise exception 'PRIVATE_PUSH_COMMIT_FAILURE';end if;return null;end $$;
	create constraint trigger fixture_push_commit_failure after insert on audit_log deferrable initially deferred for each row execute function fixture_push_commit_failure();
	insert into fixture_push_commit_failure values('push.delivery')`)
	retry := push.Result{State: push.Retry, Code: "provider_throttled", RetryAfter: time.Second}
	if err := h.push.Complete(h.ctx, *claim, retry); !errors.Is(err, push.ErrUnavailable) {
		t.Fatal("failed delivery commit appeared successful", err)
	}
	if pushDeliveryCount(t, metrics, "approval", push.Retry, "provider_throttled") != 0 {
		t.Fatal("failed delivery commit emitted result")
	}
	h.exec(t, `delete from fixture_push_commit_failure`)
	if err := h.push.Complete(h.ctx, *claim, retry); err != nil {
		t.Fatal(err)
	}
	if err := h.push.Complete(h.ctx, *claim, retry); !errors.Is(err, push.ErrLease) {
		t.Fatal("old lease completed a second attempt", err)
	}
	if pushDeliveryCount(t, metrics, "approval", push.Retry, "provider_throttled") != 1 {
		t.Fatal("retry outcome lost or duplicated")
	}
	h.exec(t, `update push_deliveries set next_attempt_at=clock_timestamp()-interval '1 second' where id=$1`, claim.ID)
	current, err := h.push.Claim(h.ctx)
	if err != nil || current == nil || current.ID != claim.ID || current.LeaseID == claim.LeaseID {
		t.Fatal("retry did not retain notification identity with fresh lease", err)
	}
	var callers sync.WaitGroup
	var winners atomic.Int32
	for range 4 {
		callers.Go(func() {
			err := h.push.Complete(h.ctx, *current, push.Result{State: push.Accepted, ProviderID: strings.Repeat("c", 64)})
			if err == nil {
				winners.Add(1)
			} else if !errors.Is(err, push.ErrLease) {
				t.Error(err)
			}
		})
	}
	callers.Wait()
	if winners.Load() != 1 || pushDeliveryCount(t, metrics, "approval", push.Accepted, "none") != 1 {
		t.Fatal("concurrent completion counted more than one committed attempt")
	}
	if count, _ := commandMetric(t, metrics, "push_client_receipts_total", map[string]string{"kind": "approval", "state": "posted"}); count != 0 {
		t.Fatal("provider acceptance invented display report")
	}
	for range 4 {
		callers.Go(func() {
			if err := h.push.Receipt(h.ctx, h.actor, current.ID, "posted"); err != nil {
				t.Error(err)
			}
		})
	}
	callers.Wait()
	h.exec(t, `insert into fixture_push_commit_failure values('push.client_receipt')`)
	if err := h.push.Receipt(h.ctx, h.actor, current.ID, "opened"); !errors.Is(err, push.ErrUnavailable) {
		t.Fatal("failed receipt commit appeared successful", err)
	}
	if count, _ := commandMetric(t, metrics, "push_client_receipts_total", map[string]string{"kind": "approval", "state": "opened"}); count != 0 {
		t.Fatal("failed receipt commit emitted report")
	}
	h.exec(t, `delete from fixture_push_commit_failure`)
	for _, state := range []string{"opened", "blocked", "posted", "opened"} {
		if err := h.push.Receipt(h.ctx, h.actor, current.ID, state); err != nil {
			t.Fatal(err)
		}
	}
	for _, state := range []string{"posted", "opened", "blocked"} {
		if count, _ := commandMetric(t, metrics, "push_client_receipts_total", map[string]string{"kind": "approval", "state": state}); count != 1 {
			t.Fatal("client state retries lost deduplication", state, count)
		}
		if count, sum := commandMetric(t, metrics, "push_client_receipt_age_seconds", map[string]string{"kind": "approval", "state": state}); count != 1 || sum <= 0 {
			t.Fatal("missing newly inserted receipt interval", state, count, sum)
		}
	}
	var deliveries, receipts, pending int
	if err := h.database.DB.QueryRowContext(h.ctx, `select count(*) filter(where action='push.delivery' and metadata->>'kind'='approval'),count(*) filter(where action='push.client_receipt'),(select count(*) from approvals where state='pending') from audit_log`).Scan(&deliveries, &receipts, &pending); err != nil || deliveries != 2 || receipts != 3 || pending != 1 {
		t.Fatal("metrics differ from audit or reports changed interaction authority", err)
	}
	wrong := h.actor
	wrong.DeviceID = approvalTestUUID(t)
	if err := h.push.Receipt(h.ctx, wrong, current.ID, "posted"); !errors.Is(err, push.ErrAccess) {
		t.Fatal("foreign device report admitted", err)
	}
	response := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
	for _, private := range []string{input.Address, input.BindingID, revokeSecret, current.ID, current.LeaseID, h.actor.DeviceID, h.connection.RuntimeID, strings.Repeat("c", 64), "PRIVATE_PUSH_COMMIT_FAILURE"} {
		if strings.Contains(response.Body.String(), private) {
			t.Fatal("push metrics exposed identity, provider address, proof or error text")
		}
	}
}

func TestPushMetricsUseFinalCommittedStateAndClampUnknownCodes(t *testing.T) {
	for _, scenario := range []string{"invalid_endpoint", "retry_expired", "unknown_clock"} {
		t.Run(scenario, func(t *testing.T) {
			h := newPushFixture(t)
			_, _, claim, _ := h.register(t, "c"+strings.Repeat("B", 21))
			metrics := observability.New()
			if err := h.database.ConfigurePushMetrics(metrics); err != nil {
				t.Fatal(err)
			}
			result := push.Result{State: push.InvalidEndpoint, Code: "provider_unregistered"}
			state, code := push.Failed, "provider_unregistered"
			if scenario == "retry_expired" {
				result = push.Result{State: push.Retry, Code: "provider_throttled", RetryAfter: time.Hour}
				state, code = push.Expired, "expired"
			}
			if scenario == "unknown_clock" {
				result = push.Result{State: push.Failed, Code: "private_unknown_code"}
				state, code = push.Failed, "other"
				h.exec(t, `update push_deliveries set created_at=expires_at-interval '1 microsecond' where id=$1`, claim.ID)
			}
			if err := h.push.Complete(h.ctx, claim, result); err != nil {
				t.Fatal(err)
			}
			if pushDeliveryCount(t, metrics, "challenge", state, code) != 1 {
				t.Fatal("metric used raw provider result instead of committed state")
			}
			if scenario == "unknown_clock" {
				if count, _ := commandMetric(t, metrics, "push_clock_anomalies_total", map[string]string{"source": "delivery"}); count != 1 {
					t.Fatal("negative delivery interval not observed")
				}
				if count, _ := commandMetric(t, metrics, "push_delivery_age_seconds", map[string]string{"kind": "challenge", "state": state}); count != 0 {
					t.Fatal("negative delivery interval entered histogram")
				}
			}
		})
	}
}
