package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

func testPostgresSessionArchive(t *testing.T, ctx context.Context, postgres *Postgres, ticket TicketRedemption, hostReceipt RelayCommandReceipt, sessionID string) {
	t.Helper()
	const archiveID = "aaaaaaaa-3333-4333-8333-333333333333"
	const restoreID = "bbbbbbbb-3333-4333-8333-333333333333"
	hash := sha256.Sum256([]byte("epoch-bound archive body"))
	digest := hex.EncodeToString(hash[:])
	questionTicket := ticket
	questionTicket.Scope.Actions = []string{"session.read", "question.answer"}
	if err := postgres.AuthorizeRealtimeQuestion(ctx, questionTicket, sessionID); err != nil {
		t.Fatalf("live question fixture denied: %v", err)
	}
	for _, variant := range []string{"action", "scope", "version", "key", "user"} {
		invalid := ticket
		switch variant {
		case "action":
			invalid.Scope.Actions = []string{"session.read"}
		case "scope":
			invalid.Scope.Sessions, invalid.Scope.Workspaces = []string{}, []string{}
		case "version":
			invalid.GrantVersion++
		case "key":
			invalid.DeviceKeyVersion++
		case "user":
			invalid.UserID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
		}
		if _, err := postgres.RecordRealtimeCommand(ctx, invalid, "session.archive", archiveID, sessionID, digest); !errors.Is(err, ErrAccessDenied) {
			t.Fatalf("archive accepted %s: %v", variant, err)
		}
	}
	status, err := postgres.RecordRealtimeCommand(ctx, ticket, "session.archive", archiveID, sessionID, digest)
	if err != nil || status.State != "received" {
		t.Fatalf("archive admission=%+v error=%v", status, err)
	}
	receipt := hostReceipt
	receipt.RequestID, receipt.SessionID, receipt.PayloadSHA256 = archiveID, sessionID, digest
	for _, state := range []string{"host_accepted", "dispatching", "settled"} {
		receipt.State = state
		if _, err := postgres.RecordRealtimeCommandReceipt(ctx, receipt); err != nil {
			t.Fatalf("archive receipt %s: %v", state, err)
		}
	}
	setState := func(state string) {
		t.Helper()
		if _, err := postgres.DB.ExecContext(ctx, `update sessions set state=$1 where id=$2`, state, sessionID); err != nil {
			t.Fatal(err)
		}
	}
	setState("archived")
	if retry, err := postgres.RecordRealtimeCommand(ctx, ticket, "session.archive", archiveID, sessionID, digest); err != nil || retry.State != "settled" {
		t.Fatalf("archived target retry=%+v error=%v", retry, err)
	}
	if _, err := postgres.RecordRealtimeCommand(ctx, ticket, "session.archive", archiveID, sessionID, hex.EncodeToString(make([]byte, 32))); !errors.Is(err, ErrCommandConflict) {
		t.Fatalf("archive ID allowed a different desired state: %v", err)
	}
	if err := postgres.AuthorizeRealtimeSessionRead(ctx, ticket, sessionID); err != nil {
		t.Fatalf("archived history denied: %v", err)
	}
	if err := postgres.AuthorizeRealtimeQuestion(ctx, questionTicket, sessionID); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("archived question claim accepted: %v", err)
	}
	for _, kind := range []string{"message.submit", "session.cancel", "question.answer"} {
		if _, err := postgres.RecordRealtimeCommand(ctx, ticket, kind, restoreID, sessionID, digest); !errors.Is(err, ErrAccessDenied) {
			t.Fatalf("archived session accepted %s: %v", kind, err)
		}
	}
	if restored, err := postgres.RecordRealtimeCommand(ctx, ticket, "session.archive", restoreID, sessionID, digest); err != nil || restored.State != "received" {
		t.Fatalf("restore admission=%+v error=%v", restored, err)
	}
	setState("unavailable")
	if _, err := postgres.RecordRealtimeCommand(ctx, ticket, "session.archive", restoreID, sessionID, digest); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("unavailable session accepted archive/restore: %v", err)
	}
	setState("running")
}
