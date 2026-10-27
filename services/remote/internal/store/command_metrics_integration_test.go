package store

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"dsh-mobile-ustc/services/remote/internal/files"
	"dsh-mobile-ustc/services/remote/internal/observability"
)

func commandMetric(t *testing.T, metrics *observability.Metrics, name string, labels map[string]string) (float64, float64) {
	t.Helper()
	families, err := metrics.Gatherer().Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != "dsh_remote_"+name {
			continue
		}
		for _, metric := range family.Metric {
			if len(metric.Label) != len(labels) {
				continue
			}
			match := true
			for _, label := range metric.Label {
				if labels[label.GetName()] != label.GetValue() {
					match = false
				}
			}
			if match {
				if metric.Histogram != nil {
					return float64(metric.GetHistogram().GetSampleCount()), metric.GetHistogram().GetSampleSum()
				}
				return metric.GetCounter().GetValue(), 0
			}
		}
	}
	return 0, 0
}

func commandTransitionCount(t *testing.T, metrics *observability.Metrics, action, from, to, origin string) float64 {
	t.Helper()
	value, _ := commandMetric(t, metrics, "command_transitions_total", map[string]string{"action": action, "from": from, "to": to, "origin": origin})
	return value
}

func fixtureReceipt(h *messageFileFixture, id string) RelayCommandReceipt {
	return RelayCommandReceipt{InstallationID: h.host.InstallationID, KeyVersion: h.host.KeyVersion, RuntimeID: h.host.RuntimeID, RuntimeEpoch: h.host.RuntimeEpoch, ConnectionID: h.host.ConnectionID, DeviceID: h.ticket.DeviceID, RequestID: id, SessionID: h.file.SessionID, PayloadSHA256: strings.Repeat("a", 64), State: "host_accepted"}
}

func TestCommandMetricsCountOnlyCommittedTransitionsUnderConcurrentRetries(t *testing.T) {
	h := newMessageFileFixture(t)
	metrics := observability.New()
	if err := h.database.ConfigureCommandMetrics(metrics); err != nil {
		t.Fatal(err)
	}
	if err := h.database.ConfigureCommandMetrics(observability.New()); !errors.Is(err, ErrDatabaseConfig) {
		t.Fatal("live observer was replaced")
	}
	id := approvalTestUUID(t)
	digest := strings.Repeat("a", 64)
	var callers sync.WaitGroup
	for range 8 {
		callers.Go(func() {
			if _, err := h.database.RecordRealtimeCommand(h.ctx, h.ticket, "message.submit", id, h.file.SessionID, digest); err != nil {
				t.Error(err)
			}
		})
	}
	callers.Wait()
	if got := commandTransitionCount(t, metrics, "message.submit", "none", "received", "device"); got != 1 {
		t.Fatal("concurrent request retries duplicated creation", got)
	}
	if count, _ := commandMetric(t, metrics, "command_store_duration_seconds", map[string]string{"operation": "admit", "result": "ok"}); count != 8 {
		t.Fatal("attempt timing lost retries", count)
	}
	wrong := h.ticket
	wrong.GrantVersion++
	if _, err := h.database.RecordRealtimeCommand(h.ctx, wrong, "message.submit", approvalTestUUID(t), h.file.SessionID, digest); !errors.Is(err, ErrAccessDenied) {
		t.Fatal(err)
	}
	if _, err := h.database.RecordRealtimeCommand(h.ctx, h.ticket, "message.submit", id, h.file.SessionID, strings.Repeat("b", 64)); !errors.Is(err, ErrCommandConflict) {
		t.Fatal(err)
	}
	h.exec(t, `create function fixture_command_commit_failure() returns trigger language plpgsql as $$ begin if new.action='command.receipt' then raise exception 'fixture deferred commit failure';end if;return null;end $$;
        create constraint trigger fixture_command_commit_failure after insert on audit_log deferrable initially deferred for each row execute function fixture_command_commit_failure()`)
	receipt := fixtureReceipt(h, id)
	if _, err := h.database.RecordRealtimeCommandReceipt(h.ctx, receipt); !errors.Is(err, ErrDatabaseUnavailable) {
		t.Fatal("deferred failure did not abort commit", err)
	}
	if got := commandTransitionCount(t, metrics, "message.submit", "received", "host_accepted", "host"); got != 0 {
		t.Fatal("uncommitted host receipt was counted", got)
	}
	var state string
	if err := h.database.DB.QueryRowContext(h.ctx, `select state from commands where request_id=$1`, id).Scan(&state); err != nil || state != "received" {
		t.Fatal("rollback did not retain prior state", state, err)
	}
	h.exec(t, `drop trigger fixture_command_commit_failure on audit_log;drop function fixture_command_commit_failure()`)
	for range 4 {
		callers.Go(func() {
			if _, err := h.database.RecordRealtimeCommandReceipt(h.ctx, receipt); err != nil {
				t.Error(err)
			}
		})
	}
	callers.Wait()
	if got := commandTransitionCount(t, metrics, "message.submit", "received", "host_accepted", "host"); got != 1 {
		t.Fatal("concurrent receipts counted more than one transition", got)
	}
	for range 3 {
		if _, err := h.database.CommandStatus(h.ctx, UserIdentity{Issuer: "https://id.example.edu", Subject: "owner-subject"}, h.ticket.DeviceID, id); err != nil {
			t.Fatal(err)
		}
	}
	if got := commandTransitionCount(t, metrics, "message.submit", "received", "host_accepted", "host"); got != 1 {
		t.Fatal("status reads counted transitions", got)
	}
	for _, result := range []string{"denied", "conflict"} {
		if count, _ := commandMetric(t, metrics, "command_store_duration_seconds", map[string]string{"operation": "admit", "result": result}); count != 1 {
			t.Fatal("store attempt classification missing", result, count)
		}
	}
	if count, _ := commandMetric(t, metrics, "command_store_duration_seconds", map[string]string{"operation": "receipt", "result": "error"}); count != 1 {
		t.Fatal("failed commit attempt disappeared", count)
	}
	for _, check := range []struct {
		name   string
		labels map[string]string
	}{
		{"command_state_entry_age_seconds", map[string]string{"action": "message.submit", "state": "host_accepted"}},
		{"command_state_dwell_seconds", map[string]string{"action": "message.submit", "from": "received", "to": "host_accepted"}},
	} {
		if count, _ := commandMetric(t, metrics, check.name, check.labels); count != 1 {
			t.Fatal("timing duplicated or disappeared", check.name, count)
		}
	}
	// Database wall-clock anomalies must not become artificial fast samples.
	h.exec(t, `update commands set created_at=clock_timestamp()+interval '1 hour',updated_at=clock_timestamp()+interval '1 hour' where request_id=$1`, id)
	receipt.State = "agent_queued"
	if _, err := h.database.RecordRealtimeCommandReceipt(h.ctx, receipt); err != nil {
		t.Fatal(err)
	}
	if got := commandTransitionCount(t, metrics, "message.submit", "host_accepted", "agent_queued", "host"); got != 1 {
		t.Fatal("valid state change was lost with bad timestamps", got)
	}
	if count, _ := commandMetric(t, metrics, "command_state_entry_age_seconds", map[string]string{"action": "message.submit", "state": "agent_queued"}); count != 0 {
		t.Fatal("negative database age was sampled")
	}
	for _, interval := range []string{"age", "dwell"} {
		if count, _ := commandMetric(t, metrics, "command_timestamp_anomalies_total", map[string]string{"interval": interval}); count != 1 {
			t.Fatal("timestamp anomaly missing", interval, count)
		}
	}
	w := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	for _, private := range []string{id, h.file.ID, h.ticket.DeviceID, h.ticket.UserID, h.ticket.RuntimeID, digest} {
		if strings.Contains(w.Body.String(), private) {
			t.Fatal("command metric exposed resource metadata")
		}
	}
}

func TestCommandMetricsUnknownResolutionAndCreationDoNotFabricateStages(t *testing.T) {
	h := newMessageFileFixture(t)
	metrics := observability.New()
	if err := h.database.ConfigureCommandMetrics(metrics); err != nil {
		t.Fatal(err)
	}
	h.exec(t, `update runtime_grants set scope=jsonb_set(scope,'{actions}',(scope->'actions')||'["session.create","session.cancel","session.archive","question.answer"]'::jsonb)`)
	var raw []byte
	if err := h.database.DB.QueryRowContext(h.ctx, `select scope from runtime_grants where runtime_id=$1`, h.ticket.RuntimeID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(raw, &h.ticket.Scope) != nil {
		t.Fatal("fixture scope")
	}
	for _, action := range []string{"message.submit", "session.cancel", "session.archive", "question.answer", "session.create"} {
		id := approvalTestUUID(t)
		receipt := fixtureReceipt(h, id)
		session := h.file.SessionID
		if action == "session.create" {
			workspace := h.ticket.Scope.Workspaces[0]
			for range 2 {
				if _, err := h.database.RecordRealtimeSessionCreate(h.ctx, h.ticket, id, workspace, receipt.PayloadSHA256); err != nil {
					t.Fatal(err)
				}
			}
			session, receipt.SessionID, receipt.WorkspaceID = "", "", workspace
		} else {
			for range 2 {
				if _, err := h.database.RecordRealtimeCommand(h.ctx, h.ticket, action, id, session, receipt.PayloadSHA256); err != nil {
					t.Fatal(err)
				}
			}
		}
		for range 2 {
			if _, err := h.database.MarkRealtimeCommandUnknown(h.ctx, h.ticket, id, session, receipt.PayloadSHA256); err != nil {
				t.Fatal(err)
			}
		}
		if got := commandTransitionCount(t, metrics, action, "received", "outcome_unknown", "relay"); got != 1 {
			t.Fatal("unknown retry counted twice", action, got)
		}
		for range 2 {
			if _, err := h.database.RecordRealtimeCommandReceipt(h.ctx, receipt); err != nil {
				t.Fatal(err)
			}
		}
		if got := commandTransitionCount(t, metrics, action, "outcome_unknown", "host_accepted", "host"); got != 1 {
			t.Fatal("resolution did not preserve its actual edge", action, got)
		}
		receipt.State = "rejected"
		if _, err := h.database.RecordRealtimeCommandReceipt(h.ctx, receipt); err != nil {
			t.Fatal(err)
		}
		if got := commandTransitionCount(t, metrics, action, "host_accepted", "agent_queued", "host"); got != 0 {
			t.Fatal("absent native stage was fabricated", action)
		}
	}
}

func TestCommandMetricsFileAdmissionRollbackAndLegacyActions(t *testing.T) {
	h := newMessageFileFixture(t)
	metrics := observability.New()
	if err := h.database.ConfigureCommandMetrics(metrics); err != nil {
		t.Fatal(err)
	}
	id := approvalTestUUID(t)
	if _, err := h.record(t, id, h.file.ID); !errors.Is(err, files.ErrStale) {
		t.Fatal("unstaged file fixture was admitted", err)
	}
	if got := commandTransitionCount(t, metrics, "message.submit", "none", "received", "device"); got != 0 {
		t.Fatal("rolled-back file command counted", got)
	}
	if count, _ := commandMetric(t, metrics, "command_store_duration_seconds", map[string]string{"operation": "file_admit", "result": "not_ready"}); count != 1 {
		t.Fatal("file staging wait misclassified", count)
	}
	h.stage(t, h.file)
	for range 2 {
		if _, err := h.record(t, id, h.file.ID); err != nil {
			t.Fatal(err)
		}
	}
	if got := commandTransitionCount(t, metrics, "message.submit", "none", "received", "device"); got != 1 {
		t.Fatal("file retry counted again", got)
	}
	h.exec(t, `update commands set action=null where request_id=$1`, id)
	if _, err := h.database.MarkRealtimeCommandUnknown(h.ctx, h.ticket, id, h.file.SessionID, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if got := commandTransitionCount(t, metrics, "other", "received", "outcome_unknown", "relay"); got != 1 {
		t.Fatal("legacy action became dynamic metadata", got)
	}
}
