package store

import (
	"context"
	"database/sql"
	"errors"
	"slices"
)

// AuthorizeRealtimeCommandReceipt checks the receiving socket's ticket, not
// merely the device's broader grant. One device can hold differently scoped
// sockets at the same time. Receipt delivery does not require session.read.
func (postgres *Postgres) AuthorizeRealtimeCommandReceipt(ctx context.Context, ticket TicketRedemption, status CommandStatus) error {
	if err := postgres.ValidateRealtimeLease(ctx, ticket); err != nil {
		return err
	}
	if !grantUUIDPattern.MatchString(status.RequestID) || !validSHA256Hex(status.PayloadSHA256) {
		return ErrAccessDenied
	}
	var sessionID, creationWorkspace, sessionWorkspace sql.NullString
	err := postgres.DB.QueryRowContext(ctx, `
		select c.session_id::text, c.workspace_id::text, s.workspace_id::text
		from command_records c
		left join sessions s on s.runtime_id = c.runtime_id and s.id = c.session_id
		where c.device_id = $1 and c.user_id = $2 and c.runtime_id = $3
		  and c.request_id = $4 and c.payload_sha256 = $5`, ticket.DeviceID, ticket.UserID, ticket.RuntimeID, status.RequestID, status.PayloadSHA256).
		Scan(&sessionID, &creationWorkspace, &sessionWorkspace)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrAccessDenied
	}
	if err != nil {
		return ErrDatabaseUnavailable
	}
	if creationWorkspace.Valid {
		if status.WorkspaceID != creationWorkspace.String || !slices.Contains(ticket.Scope.Workspaces, creationWorkspace.String) ||
			(sessionID.Valid && (!sessionWorkspace.Valid || sessionWorkspace.String != creationWorkspace.String)) {
			return ErrAccessDenied
		}
		if status.SessionID != "" && status.SessionID != sessionID.String {
			return ErrAccessDenied
		}
		return nil
	}
	if !sessionID.Valid || status.WorkspaceID != "" || status.SessionID != sessionID.String || !scopeIncludesSession(ticket.Scope, sessionID.String, sessionWorkspace) {
		return ErrAccessDenied
	}
	return nil
}
