package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

func testPostgresSessionCreation(t *testing.T, ctx context.Context, postgres *Postgres, ticket TicketRedemption, hostReceipt RelayCommandReceipt, workspaceID, existingSessionID string) {
	t.Helper()
	const requestID = "dddddddd-2222-4222-8222-222222222222"
	digestBytes := sha256.Sum256([]byte("canonical workspace creation body"))
	digest := hex.EncodeToString(digestBytes[:])
	creationTicket := ticket
	creationTicket.Scope.Actions = []string{"session.create"}
	for _, variant := range []string{"action", "scope", "key", "version", "user", "workspace"} {
		invalid := creationTicket
		otherID := "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
		target := workspaceID
		switch variant {
		case "action":
			invalid.Scope.Actions = []string{"message.submit"}
		case "scope":
			invalid.Scope.Workspaces = []string{}
		case "key":
			invalid.DeviceKeyVersion++
		case "version":
			invalid.GrantVersion++
		case "user":
			invalid.UserID = otherID
		case "workspace":
			target = otherID
			invalid.Scope.Workspaces = []string{otherID}
		}
		if _, err := postgres.RecordRealtimeSessionCreate(ctx, invalid, requestID, target, digest); !errors.Is(err, ErrAccessDenied) {
			t.Fatalf("session creation accepted %s: %v", variant, err)
		}
	}
	var before int
	if err := postgres.DB.QueryRowContext(ctx, `select count(*) from sessions`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	status, err := postgres.RecordRealtimeSessionCreate(ctx, creationTicket, requestID, workspaceID, digest)
	if err != nil || status.State != "received" || status.SessionID != "" || status.WorkspaceID != workspaceID {
		t.Fatalf("pending creation: status=%+v error=%v", status, err)
	}
	identity := UserIdentity{Issuer: "https://id.example.edu", Subject: "owner-subject"}
	if status, err := postgres.CommandStatus(ctx, identity, ticket.DeviceID, requestID); err != nil || status.SessionID != "" || status.WorkspaceID != workspaceID {
		t.Fatalf("pending creation status: status=%+v error=%v", status, err)
	}
	if _, err := postgres.RecordRealtimeCommand(ctx, ticket, "message.submit", requestID, existingSessionID, digest); !errors.Is(err, ErrCommandConflict) {
		t.Fatalf("creation ID reused for session operation: %v", err)
	}
	if _, err := postgres.RecordRealtimeSessionCreate(ctx, creationTicket, hostReceipt.RequestID, workspaceID, digest); !errors.Is(err, ErrCommandConflict) {
		t.Fatalf("session operation ID reused for creation: %v", err)
	}
	status, err = postgres.MarkRealtimeCommandUnknown(ctx, creationTicket, requestID, "", digest)
	if err != nil || status.State != "outcome_unknown" || status.WorkspaceID != workspaceID {
		t.Fatalf("unknown pending creation: status=%+v error=%v", status, err)
	}
	receipt := hostReceipt
	receipt.RequestID, receipt.SessionID, receipt.WorkspaceID, receipt.PayloadSHA256 = requestID, "", workspaceID, digest
	for _, state := range []string{"host_accepted", "dispatching"} {
		receipt.State = state
		if _, err := postgres.RecordRealtimeCommandReceipt(ctx, receipt); err != nil {
			t.Fatalf("creation receipt %s: %v", state, err)
		}
	}
	newSessionID, err := MobileSessionID(ticket.RuntimeID, "native:created/by/remote")
	if err != nil {
		t.Fatal(err)
	}
	item := SessionCatalogItem{SessionID: newSessionID, DSHSessionID: "native:created/by/remote", WorkspaceID: &workspaceID, State: "available", LastPersistedSeq: 3}
	receipt.State, receipt.SessionID, receipt.CreatedSession = "settled", newSessionID, &item
	for _, variant := range []string{"mapping", "workspace", "missing-catalog", "state", "connection"} {
		invalid, changed := receipt, item
		invalid.CreatedSession = &changed
		otherID := "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
		switch variant {
		case "mapping":
			changed.DSHSessionID = "another-native-session"
		case "workspace":
			changed.WorkspaceID = &otherID
		case "missing-catalog":
			invalid.CreatedSession = nil
		case "state":
			changed.State = "unavailable"
		case "connection":
			invalid.ConnectionID = otherID
		}
		if _, err := postgres.RecordRealtimeCommandReceipt(ctx, invalid); err == nil {
			t.Fatalf("creation settlement accepted %s", variant)
		}
	}
	// Reject the command update after the session insert. Both writes and audit
	// must roll back together, rather than publishing a misleading completion.
	if _, err := postgres.DB.ExecContext(ctx, `
		create function reject_creation_settlement() returns trigger language plpgsql as $$ begin raise exception 'injected settlement failure'; end $$;
		create trigger reject_creation before update on commands for each row
		when (new.workspace_id is not null and new.state = 'settled') execute function reject_creation_settlement()`); err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.RecordRealtimeCommandReceipt(ctx, receipt); !errors.Is(err, ErrDatabaseUnavailable) {
		t.Fatalf("injected settlement failure=%v", err)
	}
	var after int
	if err := postgres.DB.QueryRowContext(ctx, `select count(*) from sessions`).Scan(&after); err != nil || after != before {
		t.Fatalf("failed creation leaked session metadata: before=%d after=%d error=%v", before, after, err)
	}
	if status, err := postgres.CommandStatus(ctx, identity, ticket.DeviceID, requestID); err != nil || status.State != "dispatching" || status.SessionID != "" {
		t.Fatalf("failed creation changed status: status=%+v error=%v", status, err)
	}
	if _, err := postgres.DB.ExecContext(ctx, `drop trigger reject_creation on commands; drop function reject_creation_settlement()`); err != nil {
		t.Fatal(err)
	}
	newer := item
	newer.State, newer.LastPersistedSeq = "running", 4
	if err := postgres.SyncRealtimeSessionCatalog(ctx, RuntimeConnection{InstallationID: receipt.InstallationID, RuntimeID: receipt.RuntimeID, RuntimeEpoch: receipt.RuntimeEpoch, ConnectionID: receipt.ConnectionID}, receipt.KeyVersion, false, []SessionCatalogItem{newer}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		status, err := postgres.RecordRealtimeCommandReceipt(ctx, receipt)
		if err != nil || status.State != "settled" || status.SessionID != newSessionID || status.WorkspaceID != workspaceID {
			t.Fatalf("atomic creation settlement: status=%+v error=%v", status, err)
		}
	}
	if retry, err := postgres.RecordRealtimeSessionCreate(ctx, creationTicket, requestID, workspaceID, digest); err != nil || retry.State != "settled" || retry.SessionID != newSessionID {
		t.Fatalf("settled creation retry: status=%+v error=%v", retry, err)
	}
	changedDigest := sha256.Sum256([]byte("changed preset"))
	if _, err := postgres.RecordRealtimeSessionCreate(ctx, creationTicket, requestID, workspaceID, hex.EncodeToString(changedDigest[:])); !errors.Is(err, ErrCommandConflict) {
		t.Fatalf("changed creation body accepted: %v", err)
	}
	if err := postgres.DB.QueryRowContext(ctx, `select count(*) from sessions`).Scan(&after); err != nil || after != before+1 {
		t.Fatalf("creation duplicated sessions: count=%d error=%v", after, err)
	}
	var catalogState string
	var cursor int64
	if err := postgres.DB.QueryRowContext(ctx, `select state, last_persisted_seq from sessions where id = $1`, newSessionID).Scan(&catalogState, &cursor); err != nil || catalogState != "running" || cursor != 4 {
		t.Fatalf("creation result regressed newer catalog: state=%s cursor=%d error=%v", catalogState, cursor, err)
	}
}
