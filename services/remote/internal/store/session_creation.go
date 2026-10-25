package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
)

// RecordRealtimeSessionCreate authorizes the workspace before any session exists.
// Preset names and other operation parameters remain transient, covered by the digest.
func (postgres *Postgres) RecordRealtimeSessionCreate(ctx context.Context, ticket TicketRedemption, requestID, workspaceID, digest string) (CommandStatus, error) {
	if !grantUUIDPattern.MatchString(ticket.UserID) || !grantUUIDPattern.MatchString(ticket.DeviceID) ||
		!grantUUIDPattern.MatchString(ticket.RuntimeID) || !grantUUIDPattern.MatchString(requestID) ||
		!grantUUIDPattern.MatchString(workspaceID) || !validSHA256Hex(digest) {
		return CommandStatus{}, ErrGrantInvalid
	}
	if !slices.Contains(ticket.Scope.Actions, "session.create") || !slices.Contains(ticket.Scope.Workspaces, workspaceID) {
		return CommandStatus{}, ErrAccessDenied
	}
	transaction, err := postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return CommandStatus{}, ErrDatabaseUnavailable
	}
	defer transaction.Rollback()
	var scopeJSON []byte
	var orgID string
	err = transaction.QueryRowContext(ctx, `
		select g.scope, h.org_id::text from users u
		join devices d on d.user_id = u.id and d.id = $2 and d.revoked_at is null
		join org_memberships m on m.user_id = u.id
		join hosts h on h.org_id = m.org_id and h.state = 'active'
		join installations i on i.host_id = h.id and i.revoked_at is null
		join runtimes r on r.installation_id = i.id and r.id = $3 and r.revoked_at is null and `+runtimeEnrollmentApprovedSQL+`
		join runtime_grants g on g.runtime_id = r.id and g.user_id = u.id and g.grant_version = $4
		join workspaces w on w.runtime_id = r.id and w.id = $5
		where u.id = $1 and u.status = 'active' and d.key_version = $6 and d.proof_key_thumbprint = $7
		  and g.revoked_at is null and (g.expires_at is null or g.expires_at > clock_timestamp())
		for share of u, d, m, h, i, r, g, w`, ticket.UserID, ticket.DeviceID, ticket.RuntimeID,
		ticket.GrantVersion, workspaceID, ticket.DeviceKeyVersion, ticket.ProofKeyThumbprint).Scan(&scopeJSON, &orgID)
	if errors.Is(err, sql.ErrNoRows) {
		return CommandStatus{}, ErrAccessDenied
	}
	if err != nil {
		return CommandStatus{}, ErrDatabaseUnavailable
	}
	var scope GrantScope
	if json.Unmarshal(scopeJSON, &scope) != nil {
		return CommandStatus{}, ErrDatabaseUnavailable
	}
	if !grantScopeSubset(ticket.Scope, scope) || !slices.Contains(scope.Actions, "session.create") || !slices.Contains(scope.Workspaces, workspaceID) {
		return CommandStatus{}, ErrAccessDenied
	}
	return recordAuthorizedCommand(ctx, transaction, ticket, requestID, "", workspaceID, digest, orgID)
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
