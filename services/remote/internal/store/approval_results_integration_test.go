package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func resultFor(status ApprovalStatus, state, outcome string) ApprovalHostResult {
	return ApprovalHostResult{ApprovalID: status.ApprovalID, SessionID: status.SessionID, RuntimeEpoch: status.RuntimeEpoch, ExecutionID: status.ExecutionID,
		BindingSHA256: status.BindingSHA256, DecisionPayloadSHA256: status.PayloadSHA256, State: state, Outcome: outcome}
}

func acceptResultFixture(t *testing.T, fixture *approvalFixture, choice string) ApprovalStatus {
	t.Helper()
	fixture.register(t, fixture.request)
	status, err := fixture.control.Decide(fixture.ctx, fixture.principal, fixture.ticket, approvalRaw(t, fixture.request), fixture.signed(t, fixture.request, choice))
	if err != nil {
		t.Fatal(err)
	}
	return status
}

func assertApprovalResultEvents(t *testing.T, fixture *approvalFixture, expected int) {
	t.Helper()
	var audits, events int
	if err := fixture.database.DB.QueryRowContext(fixture.ctx, `select count(*) from audit_log where action = 'approval.result'`).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if err := fixture.database.DB.QueryRowContext(fixture.ctx, `select count(*) from control_outbox where topic = 'approval.result'`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if audits != expected || events != expected {
		t.Fatalf("result audit/outbox=%d/%d want %d", audits, events, expected)
	}
}

func TestPostgresApprovalDetailsRequireOwnerAndBothCurrentSocketActions(t *testing.T) {
	fixture := newApprovalFixture(t)
	fixture.register(t, fixture.request)
	scope := fixture.ticket.Scope
	scope.Actions = []string{"approval.decide", "session.read"}
	grant := GrantScope{Actions: []string{"approval.decide", "session.read", "grant.manage"}, Workspaces: scope.Workspaces, Sessions: []string{}}
	encoded, _ := json.Marshal(grant)
	if _, err := fixture.database.DB.ExecContext(fixture.ctx, `update runtime_grants set scope = $1`, encoded); err != nil {
		t.Fatal(err)
	}
	ticket := fixture.ticket
	ticket.Scope = scope
	if status, err := fixture.control.AuthorizeView(fixture.ctx, ticket, fixture.request.ApprovalID); err != nil || status.ApprovalID != fixture.request.ApprovalID {
		t.Fatalf("current owner view denied: %+v %v", status, err)
	}
	if pending, err := fixture.control.ListPending(fixture.ctx, ticket); err != nil || len(pending) != 1 {
		t.Fatalf("owner pending snapshot: %+v %v", pending, err)
	}
	for _, mutate := range []func(*TicketRedemption){
		func(ticket *TicketRedemption) { ticket.Scope.Actions = []string{"session.read"} },
		func(ticket *TicketRedemption) { ticket.Scope.Actions = []string{"approval.decide"} },
		func(ticket *TicketRedemption) { ticket.Scope.Workspaces = nil },
		func(ticket *TicketRedemption) { ticket.GrantVersion++ },
		func(ticket *TicketRedemption) { ticket.DeviceKeyVersion++ },
		func(ticket *TicketRedemption) { ticket.ProofKeyThumbprint = "other" },
		func(ticket *TicketRedemption) { ticket.UserID = approvalTestUUID(t) },
		func(ticket *TicketRedemption) { ticket.DeviceID = approvalTestUUID(t) },
		func(ticket *TicketRedemption) { ticket.RuntimeID = approvalTestUUID(t) },
	} {
		candidate := ticket
		mutate(&candidate)
		if _, err := fixture.control.AuthorizeView(fixture.ctx, candidate, fixture.request.ApprovalID); !errors.Is(err, ErrAccessDenied) {
			t.Fatalf("narrowed/changed socket view admitted: %v", err)
		}
	}
	for _, variant := range []struct{ name, change, restore string }{
		{"operator", `update runtime_grants set role = 'operator'`, `update runtime_grants set role = 'owner'`},
		{"revoked device", `update devices set revoked_at = now()`, `update devices set revoked_at = null`},
		{"revoked grant", `update runtime_grants set revoked_at = now()`, `update runtime_grants set revoked_at = null`},
		{"removed action", `update runtime_grants set scope = jsonb_set(scope, '{actions}', '["session.read","grant.manage"]')`, `update runtime_grants set scope = jsonb_set(scope, '{actions}', '["approval.decide","session.read","grant.manage"]')`},
		{"unavailable", `update sessions set state = 'unavailable'`, `update sessions set state = 'running'`},
		{"moved workspace", `update sessions set workspace_id = null`, `update sessions set workspace_id = '77777777-7777-4777-8777-777777777777'`},
	} {
		t.Run(variant.name, func(t *testing.T) {
			if _, err := fixture.database.DB.ExecContext(fixture.ctx, variant.change); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if _, err := fixture.database.DB.ExecContext(fixture.ctx, variant.restore); err != nil {
					t.Fatal(err)
				}
			})
			if _, err := fixture.control.AuthorizeView(fixture.ctx, ticket, fixture.request.ApprovalID); !errors.Is(err, ErrAccessDenied) {
				t.Fatalf("stale owner view admitted: %v", err)
			}
		})
	}
	if err := fixture.database.DetachRuntimeConnection(fixture.ctx, fixture.connection.InstallationID, fixture.connection.RuntimeID, fixture.connection.RuntimeEpoch, fixture.connection.ConnectionID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.control.AuthorizeView(fixture.ctx, ticket, fixture.request.ApprovalID); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("offline host served full details: %v", err)
	}
	if status, err := fixture.control.AuthorizeStatus(fixture.ctx, ticket, fixture.request.ApprovalID); err != nil || status.State != "invalidated" {
		t.Fatalf("offline metadata disappeared: %+v %v", status, err)
	}
	if pending, err := fixture.control.ListPending(fixture.ctx, ticket); err != nil || len(pending) != 0 {
		t.Fatalf("offline pending revived: %+v %v", pending, err)
	}
}

func TestPostgresApprovalHostResultsPersistMonotonicallyAndDoNotMintPermission(t *testing.T) {
	fixture := newApprovalFixture(t)
	status := acceptResultFixture(t, fixture, "allow_once")
	provider, _ := newTestLeaseProvider(t, fixture, time.Now().Add(time.Hour))
	for index, state := range []string{"approved", "consumed", "settled"} {
		outcome := ""
		if state == "settled" {
			outcome = "succeeded"
		}
		for range 2 {
			var err error
			status, err = fixture.control.RecordResult(fixture.ctx, fixture.connection, 1, resultFor(status, state, outcome))
			if err != nil || status.HostState != state || status.Outcome != outcome {
				t.Fatalf("host %s: %+v %v", state, status, err)
			}
		}
		assertApprovalResultEvents(t, fixture, index+1)
		if state != "approved" {
			if compact, err := provider.Issue(fixture.ctx, fixture.connection, 1, approvalRaw(t, fixture.request)); err == nil || compact != "" {
				t.Fatal("host result re-enabled execution authority")
			}
		}
	}
	for _, earlier := range []string{"approved", "consumed", "outcome_unknown"} {
		current, err := fixture.control.RecordResult(fixture.ctx, fixture.connection, 1, resultFor(status, earlier, ""))
		if err != nil || current.HostState != "settled" || current.Outcome != "succeeded" {
			t.Fatalf("old receipt downgraded known result: %+v %v", current, err)
		}
	}
	for _, conflict := range []ApprovalHostResult{resultFor(status, "settled", "failed"), resultFor(status, "invalidated", ""), resultFor(status, "denied", "")} {
		if _, err := fixture.control.RecordResult(fixture.ctx, fixture.connection, 1, conflict); !errors.Is(err, ErrApprovalConflict) {
			t.Fatalf("conflicting final result replaced history: %v", err)
		}
	}
	assertApprovalResultEvents(t, fixture, 3)
}

func TestPostgresApprovalHistoricalSettlementSurvivesReconnectAndRevokedPhone(t *testing.T) {
	fixture := newApprovalFixture(t)
	status := acceptResultFixture(t, fixture, "allow_once")
	var err error
	status, err = fixture.control.RecordResult(fixture.ctx, fixture.connection, 1, resultFor(status, "consumed", ""))
	if err != nil {
		t.Fatal(err)
	}
	old := fixture.connection
	replacement, err := fixture.database.AttachRuntimeConnection(fixture.ctx, RuntimeConnectionInput{InstallationID: old.InstallationID, RuntimeID: old.RuntimeID, KeyVersion: 1,
		RuntimeEpoch: approvalTestUUID(t), ConnectionID: approvalTestUUID(t), DSHVersion: "0.2.1-rc.2", ApplicationVersion: "npm-dsh", PluginVersion: "test", ProtocolVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	var uncertain, hostState string
	if err := fixture.database.DB.QueryRowContext(fixture.ctx, `select state, host_state from approvals where id = $1`, status.ApprovalID).Scan(&uncertain, &hostState); err != nil || uncertain != "outcome_unknown" || hostState != "consumed" {
		t.Fatalf("lost connection manufactured execution result: state=%s host=%s error=%v", uncertain, hostState, err)
	}
	if _, err := fixture.control.RecordResult(fixture.ctx, old, 1, resultFor(status, "settled", "failed")); !errors.Is(err, ErrRuntimeConnectionStale) {
		t.Fatalf("old connection reported after takeover: %v", err)
	}
	// Revocation forbids new authority, while the installation still records a real
	// old native result. No phone body/current grant is needed to preserve history.
	if _, err := fixture.database.DB.ExecContext(fixture.ctx, `update devices set revoked_at = now(); update runtime_grants set revoked_at = now()`); err != nil {
		t.Fatal(err)
	}
	reconciled, err := fixture.control.RecordResult(fixture.ctx, replacement, 1, resultFor(status, "settled", "failed"))
	if err != nil || reconciled.HostState != "settled" || reconciled.Outcome != "failed" || reconciled.RuntimeEpoch != old.RuntimeEpoch {
		t.Fatalf("historical settlement: %+v %v", reconciled, err)
	}
	assertApprovalResultEvents(t, fixture, 2)
}

func TestPostgresApprovalHostRejectionCancellationAndUnknownRequireMatchingEvidence(t *testing.T) {
	for _, choice := range []string{"pending", "reject", "allow_once"} {
		t.Run(choice, func(t *testing.T) {
			fixture := newApprovalFixture(t)
			var status ApprovalStatus
			if choice == "pending" {
				status = fixture.register(t, fixture.request)
			} else {
				status = acceptResultFixture(t, fixture, choice)
			}
			for _, field := range []string{"approval", "session", "epoch", "execution", "binding", "decision"} {
				candidate := resultFor(status, "cancelled", "")
				switch field {
				case "approval":
					candidate.ApprovalID = approvalTestUUID(t)
				case "session":
					candidate.SessionID = approvalTestUUID(t)
				case "epoch":
					candidate.RuntimeEpoch = approvalTestUUID(t)
				case "execution":
					candidate.ExecutionID = approvalTestUUID(t)
				case "binding":
					candidate.BindingSHA256 = strings.Repeat("c", 64)
				case "decision":
					candidate.DecisionPayloadSHA256 = strings.Repeat("d", 64)
				}
				if _, err := fixture.control.RecordResult(fixture.ctx, fixture.connection, 1, candidate); err == nil {
					t.Fatalf("changed %s report admitted", field)
				}
			}
			state := "cancelled"
			if choice == "reject" {
				state = "denied"
			}
			if choice == "allow_once" {
				state = "outcome_unknown"
			}
			status, err := fixture.control.RecordResult(fixture.ctx, fixture.connection, 1, resultFor(status, state, ""))
			if err != nil || status.HostState != state {
				t.Fatalf("terminal host result: %+v %v", status, err)
			}
			if choice != "allow_once" {
				if _, err := fixture.control.RecordResult(fixture.ctx, fixture.connection, 1, resultFor(status, "settled", "succeeded")); !errors.Is(err, ErrApprovalConflict) {
					t.Fatalf("unapproved/denied request became executed: %v", err)
				}
			}
			assertApprovalResultEvents(t, fixture, 1)
		})
	}
}

func TestPostgresApprovalResultAuditAndCASFailuresRollbackTheNativeFact(t *testing.T) {
	fixture := newApprovalFixture(t)
	status := acceptResultFixture(t, fixture, "allow_once")
	for _, target := range []string{"approvals", "audit_log", "control_outbox"} {
		t.Run(target, func(t *testing.T) {
			body, operation := "raise exception 'test unavailable';", "insert"
			if target == "approvals" {
				body, operation = "return null;", "update"
			}
			if _, err := fixture.database.DB.ExecContext(fixture.ctx, `create function reject_result() returns trigger language plpgsql as $$ begin `+body+` end $$; create trigger reject_result before `+operation+` on `+target+` for each row execute function reject_result()`); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if _, err := fixture.database.DB.ExecContext(fixture.ctx, `drop trigger reject_result on `+target+`; drop function reject_result()`); err != nil {
					t.Fatal(err)
				}
			})
			if _, err := fixture.control.RecordResult(fixture.ctx, fixture.connection, 1, resultFor(status, "settled", "succeeded")); !errors.Is(err, ErrDatabaseUnavailable) {
				t.Fatalf("failed durable result committed: %v", err)
			}
			assertApprovalResultEvents(t, fixture, 0)
			var state string
			if err := fixture.database.DB.QueryRowContext(fixture.ctx, `select state from approvals where id = $1`, status.ApprovalID).Scan(&state); err != nil || state != "decision_received" {
				t.Fatalf("failed result changed approval: %s %v", state, err)
			}
		})
	}
}

func TestPostgresApprovalResultMigrationKeepsSpentExecutionClosed(t *testing.T) {
	fixture := newApprovalFixture(t)
	_, file, _, _ := runtime.Caller(0)
	applyEvidenceRetentionFixtureMigration(t, fixture.ctx, fixture.database, "down")
	applyColdHistoryImportFixtureMigration(t, fixture.ctx, fixture.database, "down")
	applyEvidenceExportFixtureMigration(t, fixture.ctx, fixture.database, "down")
	fingerprintDown, err := os.ReadFile(filepath.Join(filepath.Dir(file), "../../../../deploy/sql/027_approval_evidence_fingerprints.down.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.database.DB.ExecContext(fixture.ctx, string(fingerprintDown)); err != nil {
		t.Fatal(err)
	}
	evidenceDown, err := os.ReadFile(filepath.Join(filepath.Dir(file), "../../../../deploy/sql/025_approval_decision_evidence.down.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.database.DB.ExecContext(fixture.ctx, string(evidenceDown)); err != nil {
		t.Fatal(err)
	}
	status := acceptResultFixture(t, fixture, "allow_once")
	if _, err := fixture.control.RecordResult(fixture.ctx, fixture.connection, 1, resultFor(status, "consumed", "")); err != nil {
		t.Fatal(err)
	}
	for _, direction := range []string{"down", "up"} {
		raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "../../../../deploy/sql/007_approval_host_results."+direction+".sql"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.database.DB.ExecContext(fixture.ctx, string(raw)); err != nil {
			t.Fatal(err)
		}
	}
	evidenceUp, err := os.ReadFile(filepath.Join(filepath.Dir(file), "../../../../deploy/sql/025_approval_decision_evidence.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.database.DB.ExecContext(fixture.ctx, string(evidenceUp)); err != nil {
		t.Fatal(err)
	}
	fingerprintUp, err := os.ReadFile(filepath.Join(filepath.Dir(file), "../../../../deploy/sql/027_approval_evidence_fingerprints.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.database.DB.ExecContext(fixture.ctx, string(fingerprintUp)); err != nil {
		t.Fatal(err)
	}
	applyEvidenceExportFixtureMigration(t, fixture.ctx, fixture.database, "up")
	applyColdHistoryImportFixtureMigration(t, fixture.ctx, fixture.database, "up")
	applyEvidenceRetentionFixtureMigration(t, fixture.ctx, fixture.database, "up")
	provider, _ := newTestLeaseProvider(t, fixture, time.Now().Add(time.Hour))
	if proof, err := provider.Issue(fixture.ctx, fixture.connection, 1, approvalRaw(t, fixture.request)); err == nil || proof != "" {
		t.Fatal("migration revived spent execution")
	}
	var state string
	if err := fixture.database.DB.QueryRowContext(fixture.ctx, `select state from approvals where id = $1`, status.ApprovalID).Scan(&state); err != nil || state != "outcome_unknown" {
		t.Fatalf("downgrade erased uncertainty: %s %v", state, err)
	}
	assertApprovalResultEvents(t, fixture, 1)
}

func TestPostgresApprovalControlEventsReplayOnlyMetadataReferences(t *testing.T) {
	fixture := newApprovalFixture(t)
	status := acceptResultFixture(t, fixture, "allow_once")
	provider, _ := newTestLeaseProvider(t, fixture, time.Now().Add(time.Hour))
	if _, err := provider.Issue(fixture.ctx, fixture.connection, 1, approvalRaw(t, fixture.request)); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.control.RecordResult(fixture.ctx, fixture.connection, 1, resultFor(status, "settled", "succeeded")); err != nil {
		t.Fatal(err)
	}
	events, err := fixture.database.PendingControlEvents(fixture.ctx, 128)
	if err != nil || len(events) != 4 {
		t.Fatalf("approval outbox references=%d error=%v", len(events), err)
	}
	for _, event := range events {
		if event.ApprovalID != status.ApprovalID || event.RuntimeID != status.RuntimeID {
			t.Fatalf("approval reference lost scope: %+v", event)
		}
		if err := fixture.database.MarkControlEventPublished(fixture.ctx, event.ID); err != nil {
			t.Fatal(err)
		}
	}
	if remaining, err := fixture.database.PendingControlEvents(fixture.ctx, 128); err != nil || len(remaining) != 0 {
		t.Fatalf("approval event acknowledgements failed: %+v %v", remaining, err)
	}
	var payloads string
	if err := fixture.database.DB.QueryRowContext(fixture.ctx, `select string_agg(payload::text,'') from control_outbox where topic like 'approval.%'`).Scan(&payloads); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{fixture.request.Nonce, fixture.request.CallID, "private-tool-argument", "decision_jws", "authorization_jws"} {
		if strings.Contains(payloads, secret) {
			t.Fatal("approval event exposed execution body or proof")
		}
	}
}

func TestPostgresDeviceRevocationAtomicallyTargetsOnlyAcceptedUnspentApprovalRuntimes(t *testing.T) {
	fixture := newApprovalFixture(t)
	acceptResultFixture(t, fixture, "allow_once")
	// A second accepted execution in the same runtime still needs one actor
	// event, while an unselected request contributes no device association.
	second := fixture.freshRequest(t)
	fixture.register(t, second)
	if _, err := fixture.control.Decide(fixture.ctx, fixture.principal, fixture.ticket, approvalRaw(t, second), fixture.signed(t, second, "allow_once")); err != nil {
		t.Fatal(err)
	}
	fixture.register(t, fixture.freshRequest(t))
	if _, err := fixture.database.DB.ExecContext(fixture.ctx, `create function reject_actor_event() returns trigger language plpgsql as $$ begin if NEW.topic='approval.device.revoked' then raise exception 'fixture unavailable'; end if; return NEW; end $$;
		create trigger reject_actor_event before insert on control_outbox for each row execute function reject_actor_event()`); err != nil {
		t.Fatal(err)
	}
	identity := UserIdentity{Issuer: fixture.principal.Issuer, Subject: fixture.principal.Subject}
	if err := fixture.database.RevokeDevice(fixture.ctx, identity.Issuer, identity.Subject, fixture.ticket.DeviceID); !errors.Is(err, ErrDatabaseUnavailable) {
		t.Fatalf("actor outbox failure did not roll back revocation: %v", err)
	}
	var active bool
	if err := fixture.database.DB.QueryRowContext(fixture.ctx, `select revoked_at is null from devices where id=$1`, fixture.ticket.DeviceID).Scan(&active); err != nil || !active {
		t.Fatal("failed actor event left a partial device revocation")
	}
	if _, err := fixture.database.DB.ExecContext(fixture.ctx, `drop trigger reject_actor_event on control_outbox; drop function reject_actor_event()`); err != nil {
		t.Fatal(err)
	}
	if err := fixture.database.RevokeDevice(fixture.ctx, identity.Issuer, identity.Subject, fixture.ticket.DeviceID); err != nil {
		t.Fatal(err)
	}
	events, err := fixture.database.PendingControlEvents(fixture.ctx, 128)
	if err != nil {
		t.Fatal(err)
	}
	global, scoped := 0, 0
	for _, event := range events {
		if event.Topic == "device.revoked" {
			global++
		}
		if event.Topic == "approval.device.revoked" {
			scoped++
			if event.RuntimeID != fixture.request.RuntimeID || event.DeviceID != fixture.ticket.DeviceID {
				t.Fatalf("actor event escaped its accepted runtime: %+v", event)
			}
		}
	}
	if global != 1 || scoped != 1 {
		t.Fatalf("device revocation events global=%d scoped=%d want 1/1", global, scoped)
	}
	if err := fixture.database.RevokeDevice(fixture.ctx, identity.Issuer, identity.Subject, fixture.ticket.DeviceID); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := fixture.database.DB.QueryRowContext(fixture.ctx, `select count(*) from control_outbox where topic='approval.device.revoked'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("idempotent device revocation duplicated actor invalidation")
	}
}
