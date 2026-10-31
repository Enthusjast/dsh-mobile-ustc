package store

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestForkRequiresExplicitReadCreateAndWorkspaceAuthority(t *testing.T) {
	h := questionFixture(t)
	request, digest := approvalTestUUID(t), strings.Repeat("a", 64)
	workspace := h.request.Workspace.WorkspaceID
	admit := func(ticket TicketRedemption) (CommandStatus, error) {
		return h.database.RecordRealtimeSessionFork(h.ctx, ticket, request, h.request.SessionID, workspace, digest)
	}
	if _, err := admit(h.ticket); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("ordinary read grant forked", err)
	}
	actions := []string{"session.read", "session.fork", "session.create", "command.status"}
	scope := GrantScope{Actions: actions, Workspaces: []string{workspace}, Sessions: []string{}}
	raw, _ := json.Marshal(scope)
	if _, err := h.database.DB.ExecContext(h.ctx, `update runtime_grants set scope=$1 where runtime_id=$2 and user_id=$3`, raw, h.ticket.RuntimeID, h.ticket.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := admit(h.ticket); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("old ticket acquired fork authority", err)
	}
	h.ticket.Scope = scope
	for _, missing := range actions {
		narrow := h.ticket
		narrow.Scope.Actions = nil
		for _, action := range actions {
			if action != missing {
				narrow.Scope.Actions = append(narrow.Scope.Actions, action)
			}
		}
		if _, err := admit(narrow); !errors.Is(err, ErrAccessDenied) {
			t.Fatal("missing action allowed fork", missing, err)
		}
	}
	status, err := admit(h.ticket)
	if err != nil || status.State != "received" || status.SessionID != h.request.SessionID || status.CommandType != "session.fork" {
		t.Fatal("explicit fork admission failed", status, err)
	}
	if retry, err := admit(h.ticket); err != nil || retry.PayloadSHA256 != digest || retry.SessionID != status.SessionID {
		t.Fatal("original identity changed", retry, err)
	}
	if _, err := h.database.RecordRealtimeSessionFork(h.ctx, h.ticket, request, h.request.SessionID, workspace, strings.Repeat("b", 64)); !errors.Is(err, ErrCommandConflict) {
		t.Fatal("changed anchor digest reused request", err)
	}
	if err := h.database.AuthorizeRealtimeSessionFork(h.ctx, h.ticket, h.request.SessionID, approvalTestUUID(t)); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("unrelated workspace accepted", err)
	}
}
func TestForkUnknownPreservesKnownChildAndSourceIdentity(t *testing.T) {
	for _, scenario := range []struct {
		name      string
		withdrawn bool
	}{{"missing child catalog", false}, {"withdrawn child catalog", true}} {
		t.Run(scenario.name, func(t *testing.T) {
			h := questionFixture(t)
			workspace := h.request.Workspace.WorkspaceID
			scope := GrantScope{Actions: []string{"session.read", "session.fork", "session.create", "command.status"}, Workspaces: []string{workspace}, Sessions: []string{}}
			raw, _ := json.Marshal(scope)
			if _, err := h.database.DB.ExecContext(h.ctx, `update runtime_grants set scope=$1 where runtime_id=$2 and user_id=$3`, raw, h.ticket.RuntimeID, h.ticket.UserID); err != nil {
				t.Fatal(err)
			}
			h.ticket.Scope = scope
			request, digest := approvalTestUUID(t), strings.Repeat("c", 64)
			if _, err := h.database.RecordRealtimeSessionFork(h.ctx, h.ticket, request, h.request.SessionID, workspace, digest); err != nil {
				t.Fatal(err)
			}
			child := approvalTestUUID(t)
			if scenario.withdrawn {
				if _, err := h.database.DB.ExecContext(h.ctx, `insert into sessions (id,runtime_id,workspace_id,dsh_session_id,state,last_persisted_seq,updated_at) values ($1,$2,null,$3,'unavailable',-1,clock_timestamp())`, child, h.ticket.RuntimeID, "native-child-"+child); err != nil {
					t.Fatal(err)
				}
			}
			receipt := RelayCommandReceipt{InstallationID: h.connection.InstallationID, KeyVersion: 1, RuntimeID: h.connection.RuntimeID, RuntimeEpoch: h.connection.RuntimeEpoch, ConnectionID: h.connection.ConnectionID, DeviceID: h.ticket.DeviceID, RequestID: request, SessionID: h.request.SessionID, WorkspaceID: workspace, CommandType: "session.fork", PayloadSHA256: digest}
			for _, state := range []string{"host_accepted", "dispatching"} {
				receipt.State = state
				if _, err := h.database.RecordRealtimeCommandReceipt(h.ctx, receipt); err != nil {
					t.Fatal(state, err)
				}
			}
			receipt.State = "outcome_unknown"
			receipt.ChildSessionID = child
			receipt.ForkOutcome = &SessionForkOutcome{Version: 1, WorkspaceAttachment: "failed", Checkpoint: "persisted"}
			status, err := h.database.RecordRealtimeCommandReceipt(h.ctx, receipt)
			if err != nil || status.SessionID != h.request.SessionID || status.ChildSessionID != child || status.ForkOutcome == nil || status.ForkOutcome.Checkpoint != "persisted" {
				t.Fatal("partial child lost", status, err)
			}
			receipt.ChildSessionID = ""
			receipt.ForkOutcome = nil
			status, err = h.database.RecordRealtimeCommandReceipt(h.ctx, receipt)
			if err != nil || status.ChildSessionID != child || status.ForkOutcome == nil {
				t.Fatal("sparse unknown erased child", status, err)
			}
			receipt.ChildSessionID = approvalTestUUID(t)
			receipt.ForkOutcome = &SessionForkOutcome{Version: 1, WorkspaceAttachment: "failed", Checkpoint: "persisted"}
			if _, err := h.database.RecordRealtimeCommandReceipt(h.ctx, receipt); err == nil {
				t.Fatal("child identity replacement was accepted")
			}
			var retainedChild string
			if err := h.database.DB.QueryRowContext(h.ctx, `select child_session_id::text from commands where request_id=$1`, request).Scan(&retainedChild); err != nil || retainedChild != child {
				t.Fatal("rejected replacement changed durable child identity", retainedChild, err)
			}
		})
	}
}
func TestForkOutcomeStrictVersionAndKeys(t *testing.T) {
	for _, raw := range []string{`{}`, `{"v":2,"workspace_attachment":"attached","checkpoint":"persisted"}`, `{"v":1,"workspace_attachment":"attached","checkpoint":"persisted","extra":true}`, `{"v":1,"v":1,"workspace_attachment":"attached","checkpoint":"persisted"}`, `{"v":1,"workspace_attachment":"attached","checkpoint":"yes"}`} {
		if _, err := DecodeSessionForkOutcome([]byte(raw)); err == nil {
			t.Fatal("invalid outcome accepted", raw)
		}
	}
	value, err := DecodeSessionForkOutcome([]byte(`{"v":1,"workspace_attachment":"failed","checkpoint":"persisted"}`))
	if err != nil || value.Checkpoint != "persisted" {
		t.Fatal(value, err)
	}
}
