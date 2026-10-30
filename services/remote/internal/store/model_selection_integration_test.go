package store

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestModelSelectionCommandsRequireExplicitAuthorityAndPreserveEvidence(t *testing.T) {
	h := questionFixture(t)
	id, digest := approvalTestUUID(t), strings.Repeat("a", 64)
	admit := func(ticket TicketRedemption, action, hash string) (CommandStatus, error) {
		return h.database.RecordRealtimeCommand(h.ctx, ticket, action, id, h.request.SessionID, hash)
	}
	if _, err := admit(h.ticket, "session.model.select", digest); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("ordinary answer/read permission selected a model", err)
	}
	if _, err := h.database.DB.ExecContext(h.ctx, `update runtime_grants set scope=jsonb_set(scope,'{actions}',(scope->'actions')||'["session.model.select"]')`); err != nil {
		t.Fatal(err)
	}
	if _, err := admit(h.ticket, "session.model.select", digest); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("old ticket inherited new grant action", err)
	}
	h.ticket.Scope.Actions = append(h.ticket.Scope.Actions, "session.model.select")
	if err := h.database.AuthorizeRealtimeSessionRead(h.ctx, h.ticket, h.request.SessionID); err != nil {
		t.Fatal("current read/selection scope could not read model metadata", err)
	}
	status, err := admit(h.ticket, "session.model.select", digest)
	if err != nil || status.State != "received" {
		t.Fatal("explicit model-selection permission could not admit", status, err)
	}
	if retry, err := admit(h.ticket, "session.model.select", digest); err != nil || retry != status {
		t.Fatal("model-selection retry changed its original identity", retry, err)
	}
	if _, err := admit(h.ticket, "session.model.select", strings.Repeat("b", 64)); !errors.Is(err, ErrCommandConflict) {
		t.Fatal("changed selection digest reused a request", err)
	}
	if _, err := admit(h.ticket, "question.answer", digest); !errors.Is(err, ErrCommandConflict) {
		t.Fatal("another action reused model-selection identity", err)
	}
	down, err := os.ReadFile("../../../../deploy/sql/037_model_selection.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	connection, err := h.database.DB.Conn(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_, rollbackErr := connection.ExecContext(h.ctx, string(down))
	if _, err := connection.ExecContext(h.ctx, `rollback`); err != nil || rollbackErr == nil {
		t.Fatal("rollback erased or reclassified model-selection evidence", err, rollbackErr)
	}
	var action string
	if err := h.database.DB.QueryRowContext(h.ctx, `select action from commands where device_id=$1 and request_id=$2`, h.ticket.DeviceID, id).Scan(&action); err != nil || action != "session.model.select" {
		t.Fatal("failed rollback changed command evidence", action, err)
	}
	if _, err := h.database.DB.ExecContext(h.ctx, `update runtime_grants set scope=jsonb_set(scope,'{actions}',(scope->'actions')-'session.model.select')`); err != nil {
		t.Fatal(err)
	}
	if _, err := admit(h.ticket, "session.model.select", digest); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("revoked model authority reconciled through admission", err)
	}
	if err := h.database.AuthorizeRealtimeSessionRead(h.ctx, h.ticket, h.request.SessionID); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("model metadata read retained removed selection authority", err)
	}
}

func TestModelSelectionMigrationRoundTripAndViewerIsolation(t *testing.T) {
	ctx, db := newPostgresIntegrationDatabase(t)
	for _, direction := range []string{"down", "up"} {
		raw, err := os.ReadFile("../../../../deploy/sql/037_model_selection." + direction + ".sql")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.DB.ExecContext(ctx, string(raw)); err != nil {
			t.Fatal("unused migration round trip failed", direction, err)
		}
	}
	scope := GrantScope{Actions: []string{"session.model.select"}, Workspaces: []string{}, Sessions: []string{}}
	if _, err := NormalizeTicketScope("viewer", scope); !errors.Is(err, ErrGrantInvalid) {
		t.Fatal("viewer acquired model-selection authority", err)
	}
	if _, err := NormalizeTicketScope("operator", scope); err != nil {
		t.Fatal("operator could not request explicit selection", err)
	}
}
