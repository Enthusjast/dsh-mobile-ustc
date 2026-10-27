package store

import (
	"testing"
)

func TestRecoveryQuarantineRetiresApprovalAndPushLeasesWithoutRewritingTerminalFacts(t *testing.T) {
	h := newPushFixture(t)
	active, _ := h.active(t)
	pending, _, claim, _ := h.register(t, "d"+pushTestSecret(t)[:21])
	request := h.freshRequest(t)
	waiting := h.approvalFixture.register(t, request)
	makeDecision := func(choice string) ApprovalStatus {
		t.Helper()
		request := h.freshRequest(t)
		h.approvalFixture.register(t, request)
		status, err := h.control.Decide(h.ctx, h.principal, h.ticket, approvalRaw(t, request), h.signed(t, request, choice))
		if err != nil {
			t.Fatal(err)
		}
		return status
	}
	consumed := makeDecision("allow_once")
	for _, state := range []string{"approved", "consumed"} {
		var err error
		consumed, err = h.control.RecordResult(h.ctx, h.connection, 1, resultFor(consumed, state, ""))
		if err != nil {
			t.Fatal(err)
		}
	}
	settled := makeDecision("allow_once")
	for _, state := range []string{"approved", "consumed", "settled"} {
		outcome := ""
		if state == "settled" {
			outcome = "succeeded"
		}
		var err error
		settled, err = h.control.RecordResult(h.ctx, h.connection, 1, resultFor(settled, state, outcome))
		if err != nil {
			t.Fatal(err)
		}
	}
	denied := makeDecision("reject")
	run, err := h.database.QuarantineRecovery(h.ctx, approvalTestUUID(t), OriginalDatabaseEpoch, approvalTestUUID(t))
	if err != nil {
		t.Fatal(err)
	}
	if run.Counts["approvals"] != 2 || run.Counts["push_bindings"] != 2 || run.Counts["push_deliveries"] != 1 {
		t.Fatal("live lifecycle rows were omitted", run.Counts)
	}
	for _, check := range []struct{ id, state, host string }{{waiting.ApprovalID, "invalidated", ""}, {consumed.ApprovalID, "outcome_unknown", "consumed"}, {settled.ApprovalID, settled.State, "settled"}, {denied.ApprovalID, "denied", ""}} {
		var state, host string
		if err := h.database.DB.QueryRowContext(h.ctx, `select state,coalesce(host_state,'') from approvals where id=$1`, check.id).Scan(&state, &host); err != nil || state != check.state || host != check.host {
			t.Fatal("recovery changed known native facts", state, host, err)
		}
	}
	for _, id := range []string{active.BindingID, pending.BindingID} {
		var state string
		if err := h.database.DB.QueryRowContext(h.ctx, `select state from push_bindings where id=$1`, id).Scan(&state); err != nil || state != "disabled" {
			t.Fatal("restored push channel stayed active", err)
		}
	}
	if _, err := h.push.Authorize(h.ctx, claim); err == nil {
		t.Fatal("old push lease remained usable")
	}
	var state string
	if err := h.database.DB.QueryRowContext(h.ctx, `select state from push_deliveries where id=$1`, claim.ID).Scan(&state); err != nil || state != "expired" {
		t.Fatal("leased restored notification remained deliverable", err)
	}
}
