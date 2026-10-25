package store

import (
	"errors"
	"testing"

	"dsh-mobile-ustc/services/remote/internal/files"
)

func TestPostgresExportSocketAuthorityDoesNotExpandLiteralTicketScopes(t *testing.T) {
	h := newExportFixture(t)
	h.exec(t, `update runtime_grants set scope=jsonb_set(scope,'{sessions}',jsonb_build_array($1::text))`, h.input.SessionID)
	ticket := TicketRedemption{UserID: "22222222-2222-4222-8222-222222222222", DeviceID: h.actor.DeviceID, DeviceKeyVersion: 1, ProofKeyThumbprint: h.actor.ProofKeyJKT, RuntimeID: h.input.RuntimeID, GrantVersion: 1, Scope: GrantScope{Actions: []string{"session.read", "file.download"}, Workspaces: []string{}, Sessions: []string{h.input.SessionID}}}
	narrow, err := h.database.AuthorizeRealtimeExport(h.ctx, ticket, h.input.SessionID)
	if err != nil || narrow.AllowWorkspace {
		t.Fatal("literal session grant became workspace authority")
	}
	full := ticket
	full.Scope.Workspaces = []string{"77777777-7777-4777-8777-777777777777"}
	full.Scope.Sessions = []string{}
	wide, err := h.database.AuthorizeRealtimeExport(h.ctx, full, h.input.SessionID)
	if err != nil || !wide.AllowWorkspace {
		t.Fatal("explicit workspace grant was lost")
	}
	h.input.Origin = "workspace_artifact"
	record := h.register(t)
	selector := files.ExportSelector{RequestID: h.input.RequestID, RuntimeID: h.input.RuntimeID, SessionID: h.input.SessionID, RuntimeEpoch: h.host.RuntimeEpoch, SourceID: h.input.SourceID}
	if _, _, err := h.database.LookupRealtimeExport(h.ctx, ticket, selector); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("narrow socket received workspace export reconciliation")
	}
	status, found, err := h.database.LookupRealtimeExport(h.ctx, full, selector)
	if err != nil || !found || status.ID != record.ID {
		t.Fatal("original export did not reconcile")
	}
	selector.SourceID = approvalTestUUID(t)
	if _, _, err := h.database.LookupRealtimeExport(h.ctx, full, selector); !errors.Is(err, files.ErrConflict) {
		t.Fatal("source change kept original request identity")
	}
	h.exec(t, `update runtime_grants set grant_version=grant_version+1`)
	if _, err := h.database.AuthorizeRealtimeExport(h.ctx, full, h.input.SessionID); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("old socket authority survived generation update")
	}
}
