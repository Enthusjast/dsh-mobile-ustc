package store

import (
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"dsh-mobile-ustc/services/remote/internal/files"
	"dsh-mobile-ustc/services/remote/internal/observability"
)

func handoffEventCount(t *testing.T, metrics *observability.Metrics, stage string) float64 {
	t.Helper()
	count, _ := commandMetric(t, metrics, "file_handoff_events_total", map[string]string{"stage": stage})
	return count
}

func TestFileHandoffMetricsCountCommittedMilestonesOnceUnderRetries(t *testing.T) {
	h := newHandoffFixture(t)
	metrics := observability.New()
	if err := h.database.ConfigureFileMetrics(metrics); err != nil {
		t.Fatal(err)
	}
	if err := h.database.ConfigureFileMetrics(observability.New()); !errors.Is(err, ErrDatabaseConfig) {
		t.Fatal("live file observer was replaced")
	}
	var offer *files.FileOffer
	var mu sync.Mutex
	var callers sync.WaitGroup
	for range 4 {
		callers.Go(func() {
			current, err := h.repository.IssueHandoff(h.ctx, h.host, h.file.ID, fileTestPolicy)
			if err != nil {
				t.Error(err)
			}
			if current != nil {
				mu.Lock()
				offer = current
				mu.Unlock()
			}
		})
	}
	callers.Wait()
	if offer == nil || handoffEventCount(t, metrics, "offered") != 1 {
		t.Fatal("concurrent offers lost or duplicated milestone")
	}
	if count, _ := commandMetric(t, metrics, "file_handoff_operation_duration_seconds", map[string]string{"operation": "offer", "result": "ok"}); count != 4 {
		t.Fatal("offer attempt timing lost successful no-op retries", count)
	}
	// A deferred audit trigger fails at Commit, after all state updates ran.
	h.exec(t, `create table fixture_file_commit_failure(action text);
	create function fixture_file_commit_failure() returns trigger language plpgsql as $$ begin
	if exists(select 1 from fixture_file_commit_failure where action=new.action) then raise exception 'PRIVATE_DEFERRED_FILE_COMMIT_FAILURE';end if;return null;end $$;
	create constraint trigger fixture_file_commit_failure after insert on audit_log deferrable initially deferred for each row execute function fixture_file_commit_failure();
	insert into fixture_file_commit_failure values('file.host_read')`)
	verify := func(files.ReadPermit) error { return nil }
	if _, err := h.repository.RedeemFileRead(h.ctx, offer.HandoffID, offer.DownloadToken, fileTestPolicy, verify); !errors.Is(err, files.ErrUnavailable) {
		t.Fatal("deferred failed read unexpectedly succeeded", err)
	}
	if handoffEventCount(t, metrics, "read_started") != 0 {
		t.Fatal("failed commit emitted read milestone")
	}
	if count, _ := commandMetric(t, metrics, "file_handoff_age_seconds", map[string]string{"stage": "read_started"}); count != 0 {
		t.Fatal("failed read emitted success age")
	}
	h.exec(t, `delete from fixture_file_commit_failure`)
	var winners atomic.Int32
	for range 4 {
		callers.Go(func() {
			_, err := h.repository.RedeemFileRead(h.ctx, offer.HandoffID, offer.DownloadToken, fileTestPolicy, verify)
			if err == nil {
				winners.Add(1)
			} else if !errors.Is(err, files.ErrAccess) {
				t.Error(err)
			}
		})
	}
	callers.Wait()
	if winners.Load() != 1 || handoffEventCount(t, metrics, "read_started") != 1 {
		t.Fatal("read retry did not retain one-use authority", winners.Load())
	}
	h.exec(t, `insert into fixture_file_commit_failure values('file.host_staged')`)
	stage := func(name string) error {
		return h.repository.StageHandoff(h.ctx, h.host, offer.HandoffID, h.file.SHA256, h.file.SizeBytes, name, fileTestPolicy)
	}
	const name = "PRIVATE_HOST_STAGED_NAME.txt"
	if err := stage(name); !errors.Is(err, files.ErrUnavailable) {
		t.Fatal("deferred stage commit unexpectedly succeeded", err)
	}
	if handoffEventCount(t, metrics, "staged") != 0 {
		t.Fatal("failed stage commit emitted milestone")
	}
	if count, _ := commandMetric(t, metrics, "file_handoff_read_to_stage_seconds", map[string]string{}); count != 0 {
		t.Fatal("failed stage invented completion interval")
	}
	h.exec(t, `delete from fixture_file_commit_failure`)
	for range 4 {
		callers.Go(func() {
			if err := stage(name); err != nil {
				t.Error(err)
			}
		})
	}
	callers.Wait()
	if err := stage("different.txt"); !errors.Is(err, files.ErrConflict) {
		t.Fatal("changed staged filename overwrote committed evidence", err)
	}
	if handoffEventCount(t, metrics, "staged") != 1 {
		t.Fatal("stage retries duplicated committed milestone")
	}
	for _, milestone := range []string{"read_started", "staged"} {
		if count, sum := commandMetric(t, metrics, "file_handoff_age_seconds", map[string]string{"stage": milestone}); count != 1 || sum <= 0 {
			t.Fatal("missing database interval", milestone, count, sum)
		}
	}
	if count, sum := commandMetric(t, metrics, "file_handoff_read_to_stage_seconds", map[string]string{}); count != 1 || sum <= 0 {
		t.Fatal("missing read-to-stage interval", count, sum)
	}
	for range 2 {
		if _, err := h.repository.RenewHandoff(h.ctx, h.host, offer.HandoffID, fileTestPolicy); err != nil {
			t.Fatal(err)
		}
	}
	if handoffEventCount(t, metrics, "staged") != 1 {
		t.Fatal("renewal repeated a milestone")
	}
	var readAudits, stageAudits int
	if err := h.database.DB.QueryRowContext(h.ctx, `select count(*) filter(where action='file.host_read'),count(*) filter(where action='file.host_staged') from audit_log`).Scan(&readAudits, &stageAudits); err != nil || readAudits != 1 || stageAudits != 1 {
		t.Fatal("milestones do not match committed audit", err)
	}
	response := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
	for _, private := range []string{name, "PRIVATE_DEFERRED_FILE_COMMIT_FAILURE", offer.DownloadToken, h.file.ID, h.file.SHA256, h.host.RuntimeID, h.host.ConnectionID, string(h.public), fileTestPolicy} {
		if strings.Contains(response.Body.String(), private) {
			t.Fatal("handoff metrics exposed metadata, context, key or capability")
		}
	}
}

func TestFileHandoffMetricsFailedOfferCommitAndClockAnomalies(t *testing.T) {
	h := newHandoffFixture(t)
	metrics := observability.New()
	if err := h.database.ConfigureFileMetrics(metrics); err != nil {
		t.Fatal(err)
	}
	h.exec(t, `create function fixture_offer_commit_failure() returns trigger language plpgsql as $$ begin raise exception 'PRIVATE_OFFER_COMMIT_FAILURE';end $$;
	create constraint trigger fixture_offer_commit_failure after insert on file_handoffs deferrable initially deferred for each row execute function fixture_offer_commit_failure()`)
	if offer, err := h.repository.IssueHandoff(h.ctx, h.host, h.file.ID, fileTestPolicy); !errors.Is(err, files.ErrUnavailable) || offer != nil {
		t.Fatal("failed offer leaked capability", err)
	}
	if handoffEventCount(t, metrics, "offered") != 0 {
		t.Fatal("failed offer commit emitted milestone")
	}
	h.exec(t, `drop trigger fixture_offer_commit_failure on file_handoffs`)
	offer := h.offer(t)
	// Simulate database wall-clock discontinuity without altering authority deadlines.
	h.exec(t, `update file_handoffs set created_at=clock_timestamp()+interval '1 hour' where id=$1`, offer.HandoffID)
	if _, err := h.repository.RedeemFileRead(h.ctx, offer.HandoffID, offer.DownloadToken, fileTestPolicy, func(files.ReadPermit) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := h.repository.StageHandoff(h.ctx, h.host, offer.HandoffID, h.file.SHA256, h.file.SizeBytes, "clock.txt", fileTestPolicy); err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"read_started", "staged"} {
		if handoffEventCount(t, metrics, stage) != 1 {
			t.Fatal("clock anomaly lost committed milestone", stage)
		}
		if count, _ := commandMetric(t, metrics, "file_handoff_age_seconds", map[string]string{"stage": stage}); count != 0 {
			t.Fatal("negative database age entered histogram", stage)
		}
		if count, _ := commandMetric(t, metrics, "file_clock_anomalies_total", map[string]string{"stage": stage}); count != 1 {
			t.Fatal("clock anomaly not counted", stage)
		}
	}
	if count, sum := commandMetric(t, metrics, "file_handoff_read_to_stage_seconds", map[string]string{}); count != 1 || sum <= 0 {
		t.Fatal("valid read interval lost with bad offer clock", count, sum)
	}
}
