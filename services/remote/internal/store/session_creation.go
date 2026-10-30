package store

import (
	"context"
	"database/sql"
	"slices"
	"time"
)

// RecordRealtimeSessionCreate authorizes the workspace before any session exists.
// Preset names and other operation parameters remain transient, covered by the digest.
func (postgres *Postgres) RecordRealtimeSessionCreate(ctx context.Context, ticket TicketRedemption, requestID, workspaceID, digest string) (CommandStatus, error) {
	started := time.Now()
	status, err := postgres.recordRealtimeSessionCreate(ctx, ticket, requestID, workspaceID, digest)
	postgres.observeCommandStore(ctx, "create", started, err)
	return status, err
}

func (postgres *Postgres) recordRealtimeSessionCreate(ctx context.Context, ticket TicketRedemption, requestID, workspaceID, digest string) (CommandStatus, error) {
	if !grantUUIDPattern.MatchString(ticket.UserID) || !grantUUIDPattern.MatchString(ticket.DeviceID) ||
		!grantUUIDPattern.MatchString(ticket.RuntimeID) || !grantUUIDPattern.MatchString(requestID) ||
		!grantUUIDPattern.MatchString(workspaceID) || !validSHA256Hex(digest) {
		return CommandStatus{}, ErrGrantInvalid
	}
	if !slices.Contains(ticket.Scope.Actions, "session.create") || !slices.Contains(ticket.Scope.Workspaces, workspaceID) {
		return CommandStatus{}, ErrAccessDenied
	}
	if err := postgres.admitCommandRate(ctx, ticket, "session.create", "", workspaceID, false); err != nil {
		return CommandStatus{}, err
	}
	transaction, err := postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return CommandStatus{}, ErrDatabaseUnavailable
	}
	defer transaction.Rollback()
	authority, err := authorizeCommandResources(ctx, transaction, ticket, "session.create", "", workspaceID, false)
	if err != nil {
		return CommandStatus{}, err
	}

	return recordAuthorizedCommand(ctx, transaction, ticket, requestID, "", workspaceID, digest, authority.organization, "session.create", postgres.commands.metrics)
}

func validateCreatedSession(receipt RelayCommandReceipt) error {
	item := receipt.CreatedSession
	if item == nil || item.WorkspaceID == nil || *item.WorkspaceID != receipt.WorkspaceID ||
		item.SessionID != receipt.SessionID || item.LastPersistedSeq < -1 || (item.State != "available" && item.State != "running" && item.State != "archived") {
		return ErrCommandTransition
	}
	mapped, err := MobileSessionID(receipt.RuntimeID, item.DSHSessionID)
	if err != nil || mapped != item.SessionID {
		return ErrSessionCatalogInvalid
	}
	return nil
}

func recordCreatedSession(ctx context.Context, transaction *sql.Tx, receipt RelayCommandReceipt) error {
	item := receipt.CreatedSession
	result, err := transaction.ExecContext(ctx, `
		insert into sessions (id, runtime_id, workspace_id, dsh_session_id, state, last_persisted_seq)
		values ($1, $2, $3, $4, $5, $6)
		on conflict (id) do update set
		  last_persisted_seq = greatest(sessions.last_persisted_seq, excluded.last_persisted_seq)
		where sessions.runtime_id = excluded.runtime_id and sessions.workspace_id = excluded.workspace_id
		  and sessions.dsh_session_id = excluded.dsh_session_id`, item.SessionID, receipt.RuntimeID, receipt.WorkspaceID, item.DSHSessionID, item.State, item.LastPersistedSeq)
	if err != nil {
		return ErrDatabaseUnavailable
	}
	count, err := result.RowsAffected()
	if err != nil {
		return ErrDatabaseUnavailable
	}
	if count != 1 {
		return ErrCommandConflict
	}
	return nil
}
