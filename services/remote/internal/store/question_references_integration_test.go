package store

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"dsh-mobile-ustc/services/remote/internal/push"
)

func questionFixture(t *testing.T) *approvalFixture {
	t.Helper()
	h := newApprovalFixture(t)
	if _, err := h.database.DB.ExecContext(h.ctx, `update runtime_grants set scope=jsonb_set(scope,'{actions}','["session.read","question.answer"]')`); err != nil {
		t.Fatal(err)
	}
	h.ticket.Scope.Actions = []string{"session.read", "question.answer"}
	return h
}
func questionItemFixture(t *testing.T, h *approvalFixture, kind string) QuestionReferenceItem {
	t.Helper()
	item := QuestionReferenceItem{ID: approvalTestUUID(t), SessionID: h.request.SessionID, Kind: kind, State: "pending"}
	if kind == "question" {
		expiry := time.Now().Add(2 * time.Minute).UTC().Truncate(time.Millisecond)
		item.ExpiresAt = &expiry
	}
	return item
}
func replaceQuestionConnection(t *testing.T, h *approvalFixture, epoch string) RuntimeConnection {
	t.Helper()
	conn, err := h.database.AttachRuntimeConnection(h.ctx, RuntimeConnectionInput{InstallationID: h.connection.InstallationID, KeyVersion: 1, RuntimeID: h.connection.RuntimeID,
		RuntimeEpoch: epoch, ConnectionID: approvalTestUUID(t), DSHVersion: "0.2.1-rc.2", ApplicationVersion: "npm-dsh", PluginVersion: "test", ProtocolVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err = h.database.SyncRealtimeSessionCatalog(h.ctx, conn, 1, true, []SessionCatalogItem{{SessionID: h.request.SessionID, DSHSessionID: "native-approval-session", WorkspaceID: ptr(h.request.Workspace.WorkspaceID), State: "running", LastPersistedSeq: -1}}); err != nil {
		t.Fatal(err)
	}
	return conn
}
func TestQuestionReferencesSequenceCatalogOwnershipAndEpochFences(t *testing.T) {
	h := questionFixture(t)
	first := questionItemFixture(t, h, "question")
	timed := questionItemFixture(t, h, "timed_question")
	sync := func(conn RuntimeConnection, sequence int64, items ...QuestionReferenceItem) error {
		return h.database.SyncRealtimeQuestionReferences(h.ctx, conn, 1, sequence, items)
	}
	if err := sync(h.connection, 1, first, timed); err != nil {
		t.Fatal(err)
	}
	if err := sync(h.connection, 1, first, timed); err != nil {
		t.Fatal("exact retry failed", err)
	}
	var audits int
	if h.database.DB.QueryRowContext(h.ctx, `select count(*) from audit_log where action='question.references.sync'`).Scan(&audits) != nil || audits != 1 {
		t.Fatal("lease retry created another content audit")
	}
	continued := timed
	continued.State = "continued"
	if err := sync(h.connection, 1, first, continued); !errors.Is(err, ErrQuestionReferencesConflict) {
		t.Fatal("same sequence changed content", err)
	}
	if err := sync(h.connection, 3, first, timed); !errors.Is(err, ErrQuestionReferencesConflict) {
		t.Fatal("sequence gap was accepted", err)
	}
	if err := sync(h.connection, 2, continued); err != nil {
		t.Fatal(err)
	}
	status, err := h.database.AuthorizeQuestionReference(h.ctx, h.ticket, timed.ID)
	if err != nil || status.State != "continued" || status.Availability != "online" || time.Until(status.ValidUntil) > 45*time.Second {
		t.Fatal("continued question unavailable", err, status)
	}
	ended, err := h.database.AuthorizeQuestionReference(h.ctx, h.ticket, first.ID)
	if err != nil || ended.State != "ended" || ended.Availability != "ended" {
		t.Fatal("omitted question remained live", err, ended)
	}
	unknown := continued
	unknown.ID = approvalTestUUID(t)
	unknown.SessionID = approvalTestUUID(t)
	if err := sync(h.connection, 3, unknown); !errors.Is(err, ErrQuestionReferencesInvalid) {
		t.Fatal("unknown session was accepted", err)
	}
	mutated := continued
	mutated.Kind = "question"
	expiry := time.Now().Add(time.Minute)
	mutated.ExpiresAt = &expiry
	mutated.State = "pending"
	if err := sync(h.connection, 3, mutated); !errors.Is(err, ErrQuestionReferencesInvalid) {
		t.Fatal("question kind was rewritten", err)
	}
	newConnection := replaceQuestionConnection(t, h, h.connection.RuntimeEpoch)
	if err := sync(h.connection, 3, continued); !errors.Is(err, ErrRuntimeConnectionStale) {
		t.Fatal("retired connection renewed metadata", err)
	}
	if err := sync(newConnection, 1, continued); err != nil {
		t.Fatal("new connection failed to restate original question", err)
	}
	nextEpoch := replaceQuestionConnection(t, h, approvalTestUUID(t))
	if err := sync(nextEpoch, 1, continued); !errors.Is(err, ErrQuestionReferencesInvalid) {
		t.Fatal("original ID moved to another epoch", err)
	}
	fresh := continued
	fresh.ID = approvalTestUUID(t)
	if err := sync(nextEpoch, 1, fresh); err != nil {
		t.Fatal(err)
	}
	stale, err := h.database.AuthorizeQuestionReference(h.ctx, h.ticket, continued.ID)
	if err != nil || stale.Availability != "stale_epoch" {
		t.Fatal("old epoch was not exposed as stale", err, stale)
	}
}

func TestQuestionReferencesStrictFieldsAndBudgetSurviveReconnection(t *testing.T) {
	h := questionFixture(t)
	valid := questionItemFixture(t, h, "question")
	raw, _ := json.Marshal(valid)
	var fields map[string]any
	_ = json.Unmarshal(raw, &fields)
	for _, field := range []string{"questions", "answers", "call_id", "arguments", "decision_jws"} {
		fields[field] = "PRIVATE_MUST_NOT_PERSIST"
		encoded, _ := json.Marshal(fields)
		var item QuestionReferenceItem
		if json.Unmarshal(encoded, &item) == nil {
			t.Fatal("body or authority field accepted", field)
		}
		delete(fields, field)
	}
	delete(fields, "expires_at")
	missing, _ := json.Marshal(fields)
	var item QuestionReferenceItem
	if json.Unmarshal(missing, &item) == nil {
		t.Fatal("missing native deadline accepted")
	}
	_, err := h.database.DB.ExecContext(h.ctx, `insert into question_references(id,runtime_id,runtime_epoch,connection_id,session_id,kind,state)
	 select gen_random_uuid(),$1,$2,$3,$4,'timed_question','ended' from generate_series(1,2048)`, h.connection.RuntimeID, h.connection.RuntimeEpoch, h.connection.ConnectionID, h.request.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if err = h.database.SyncRealtimeQuestionReferences(h.ctx, h.connection, 1, 1, []QuestionReferenceItem{valid}); !errors.Is(err, ErrQuestionReferencesLimited) {
		t.Fatal("new-reference budget was bypassed", err)
	}
	connection := replaceQuestionConnection(t, h, h.connection.RuntimeEpoch)
	if err = h.database.SyncRealtimeQuestionReferences(h.ctx, connection, 1, 1, []QuestionReferenceItem{valid}); !errors.Is(err, ErrQuestionReferencesLimited) {
		t.Fatal("reconnection reset reference budget", err)
	}
	if err = h.database.SyncRealtimeQuestionReferences(h.ctx, connection, 1, 1, []QuestionReferenceItem{}); err != nil {
		t.Fatal("budget prevented an empty reconciliation", err)
	}
}

func TestPushQuestionSourcesStayIndependentAndRecheckCurrentNativeMetadata(t *testing.T) {
	h := newPushFixture(t)
	binding, _ := h.active(t)
	if _, err := h.database.DB.ExecContext(h.ctx, `update runtime_grants set role='operator',scope=jsonb_set(scope,'{actions}','["session.read","question.answer"]')`); err != nil {
		t.Fatal(err)
	}
	first := questionItemFixture(t, h.approvalFixture, "question")
	timed := questionItemFixture(t, h.approvalFixture, "timed_question")
	timed.State = "continued"
	if err := h.database.SyncRealtimeQuestionReferences(h.ctx, h.connection, 1, 1, []QuestionReferenceItem{first, timed}); err != nil {
		t.Fatal(err)
	}
	if err := h.push.Plan(h.ctx); err != nil {
		t.Fatal(err)
	}
	claims := map[string]push.Claim{}
	for range 2 {
		claim, err := h.push.Claim(h.ctx)
		if err != nil || claim == nil {
			t.Fatal("independent question was not queued", err)
		}
		out, err := h.push.Authorize(h.ctx, *claim)
		if err != nil || out.NotificationID != claim.ID || out.Kind != claim.Kind {
			t.Fatal("question did not authorize", err)
		}
		claims[claim.Kind] = *claim
	}
	if len(claims) != 2 || claims["question"].ID == claims["timed_question"].ID {
		t.Fatal("same-session questions collapsed")
	}
	if err := h.database.SyncRealtimeQuestionReferences(h.ctx, h.connection, 1, 2, []QuestionReferenceItem{timed}); err != nil {
		t.Fatal(err)
	}
	ordinary := claims["question"]
	if err := h.push.Recheck(h.ctx, ordinary); !errors.Is(err, push.ErrAccess) {
		t.Fatal("ended question sent", err)
	}
	if err := h.push.Complete(h.ctx, ordinary, push.Result{State: push.Expired, Code: "authority_changed"}); err != nil {
		t.Fatal(err)
	}
	ended, err := h.push.Reference(h.ctx, h.actor, ordinary.ID)
	if err != nil || ended.State != "ended" || ended.Availability != "ended" {
		t.Fatal("ended notification fabricated native state", err, ended)
	}
	if _, err = h.database.DB.ExecContext(h.ctx, `update question_reference_feeds set lease_until=clock_timestamp()-interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	late := claims["timed_question"]
	if err = h.push.Recheck(h.ctx, late); !errors.Is(err, push.ErrUnavailable) {
		t.Fatal("expired metadata lease authorized sending", err)
	}
	unknown, err := h.push.Reference(h.ctx, h.actor, late.ID)
	if err != nil || unknown.Availability != "state_unavailable" {
		t.Fatal("online host with unavailable metadata was mislabeled", err, unknown)
	}
	if err = h.database.SyncRealtimeQuestionReferences(h.ctx, h.connection, 1, 3, []QuestionReferenceItem{timed}); err != nil {
		t.Fatal(err)
	}
	if err = h.push.Recheck(h.ctx, late); err != nil {
		t.Fatal(err)
	}
	if err = h.push.Complete(h.ctx, late, push.Result{State: push.Accepted}); err != nil {
		t.Fatal(err)
	}
	ref, err := h.push.Reference(h.ctx, h.actor, late.ID)
	if err != nil || ref.State != "continued" || ref.Availability != "online" || ref.BindingID != binding.BindingID || time.Until(ref.ExpiresAt) > 45*time.Second {
		t.Fatal("continued reference invalid", err, ref)
	}
	if err = h.database.DetachRuntimeConnection(h.ctx, h.connection.InstallationID, h.connection.RuntimeID, h.connection.RuntimeEpoch, h.connection.ConnectionID); err != nil {
		t.Fatal(err)
	}
	offline, err := h.push.Reference(h.ctx, h.actor, late.ID)
	if err != nil || offline.Availability != "host_offline" {
		t.Fatal("offline host looked actionable", err, offline)
	}
	contentTicket := h.ticket
	contentTicket.Scope.Actions = []string{"session.read"}
	if err = h.database.AuthorizeRealtimeSessionRead(h.ctx, contentTicket, timed.SessionID); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("metadata availability weakened offline content denial", err)
	}
	restored := replaceQuestionConnection(t, h.approvalFixture, h.connection.RuntimeEpoch)
	if err = h.database.SyncRealtimeQuestionReferences(h.ctx, restored, 1, 1, []QuestionReferenceItem{timed}); err != nil {
		t.Fatal(err)
	}
	if err = h.push.Plan(h.ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if h.database.DB.QueryRowContext(h.ctx, `select count(*) from push_deliveries where kind in ('question','timed_question')`).Scan(&count) != nil || count != 2 {
		t.Fatal("reconnect created another notification identity")
	}
	if _, err = h.database.DB.ExecContext(h.ctx, `update runtime_grants set scope=jsonb_set(scope,'{actions}','["session.read"]')`); err != nil {
		t.Fatal(err)
	}
	if _, err = h.push.Reference(h.ctx, h.actor, late.ID); !errors.Is(err, push.ErrAccess) {
		t.Fatal("revoked answer permission still read a notification", err)
	}
	other := h.actor
	other.ProofKeyJKT = strings.Repeat("Z", 43)
	if _, err = h.push.Reference(h.ctx, other, late.ID); !errors.Is(err, push.ErrAccess) {
		t.Fatal("notification crossed device keys", err)
	}
}
