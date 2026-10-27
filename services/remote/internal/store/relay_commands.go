package store

import (
	"context"
	"database/sql"
	"dsh-mobile-ustc/services/remote/internal/observability"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"
)

var ErrCommandConflict = errors.New("store: command request conflicts")
var ErrCommandTransition = errors.New("store: invalid command state transition")

type RelayCommandReceipt struct {
	InstallationID string
	KeyVersion     int64
	RuntimeID      string
	RuntimeEpoch   string
	ConnectionID   string
	DeviceID       string
	RequestID      string
	SessionID      string
	WorkspaceID    string
	CreatedSession *SessionCatalogItem
	PayloadSHA256  string
	State          string
}

var commandTransitions = map[string]map[string]struct{}{
	"received":        {"host_accepted": {}, "rejected": {}, "outcome_unknown": {}},
	"host_accepted":   {"dispatching": {}, "agent_queued": {}, "settled": {}, "rejected": {}, "outcome_unknown": {}},
	"dispatching":     {"agent_queued": {}, "settled": {}, "rejected": {}, "outcome_unknown": {}},
	"agent_queued":    {"observed": {}, "settled": {}, "outcome_unknown": {}},
	"observed":        {"settled": {}, "outcome_unknown": {}},
	"outcome_unknown": {"host_accepted": {}, "agent_queued": {}, "rejected": {}, "settled": {}},
}

var relayReceiptStates = map[string]struct{}{
	"host_accepted": {}, "dispatching": {}, "agent_queued": {}, "observed": {},
	"settled": {}, "rejected": {}, "outcome_unknown": {},
}

// RecordRealtimeCommand persists status and a digest; the request body remains transient.
func (postgres *Postgres) RecordRealtimeCommand(ctx context.Context, ticket TicketRedemption, commandType, requestID, sessionID, payloadSHA256 string) (CommandStatus, error) {
	started := time.Now()
	status, err := postgres.recordRealtimeCommand(ctx, ticket, commandType, requestID, sessionID, payloadSHA256, nil)
	postgres.observeCommandStore(ctx, "admit", started, err)
	return status, err
}

// admission runs under the same permission, command and resource locks as the
// command insertion. Failure rolls back both the command and its file claims.
func (postgres *Postgres) recordRealtimeCommand(ctx context.Context, ticket TicketRedemption, commandType, requestID, sessionID, payloadSHA256 string, admission func(context.Context, *sql.Tx, CommandStatus) error) (CommandStatus, error) {
	if commandType != "message.submit" && commandType != "session.cancel" && commandType != "session.archive" && commandType != "question.answer" {
		return CommandStatus{}, ErrGrantInvalid
	}
	if !grantUUIDPattern.MatchString(ticket.UserID) || !grantUUIDPattern.MatchString(ticket.DeviceID) ||
		!grantUUIDPattern.MatchString(ticket.RuntimeID) || !grantUUIDPattern.MatchString(requestID) ||
		!grantUUIDPattern.MatchString(sessionID) || !validSHA256Hex(payloadSHA256) {
		return CommandStatus{}, ErrGrantInvalid
	}
	if !slices.Contains(ticket.Scope.Actions, commandType) {
		return CommandStatus{}, ErrAccessDenied
	}
	transaction, err := postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return CommandStatus{}, ErrDatabaseUnavailable
	}
	defer transaction.Rollback()

	var currentScopeJSON []byte
	var workspaceID sql.NullString
	var sessionState, orgID string
	err = transaction.QueryRowContext(ctx, `
		select g.scope, s.workspace_id::text, s.state, h.org_id::text
		from users u
		join devices d on d.user_id = u.id and d.id = $2 and d.revoked_at is null
		join org_memberships m on m.user_id = u.id
		join hosts h on h.org_id = m.org_id and h.state = 'active'
		join installations i on i.host_id = h.id and i.revoked_at is null
		join runtimes r on r.installation_id = i.id and r.id = $3 and r.revoked_at is null and `+runtimeEnrollmentApprovedSQL+`
		join runtime_grants g on g.runtime_id = r.id and g.user_id = u.id and g.grant_version = $4
		join sessions s on s.runtime_id = r.id and s.id = $5
		where u.id = $1 and u.status = 'active' and d.key_version = $6 and d.proof_key_thumbprint = $7
		  and g.revoked_at is null and (g.expires_at is null or g.expires_at > clock_timestamp())
		for share of u, d, m, h, i, r, g, s`,
		ticket.UserID, ticket.DeviceID, ticket.RuntimeID, ticket.GrantVersion, sessionID,
		ticket.DeviceKeyVersion, ticket.ProofKeyThumbprint).Scan(&currentScopeJSON, &workspaceID, &sessionState, &orgID)
	if errors.Is(err, sql.ErrNoRows) {
		return CommandStatus{}, ErrAccessDenied
	}
	if err != nil {
		return CommandStatus{}, ErrDatabaseUnavailable
	}
	// Archived sessions remain valid archive targets. File admission hooks may
	// reconcile an existing intent there, but must reject all fresh admission.
	if sessionState != "available" && sessionState != "running" && !(sessionState == "archived" && (commandType == "session.archive" || commandType == "message.submit" && admission != nil)) {
		return CommandStatus{}, ErrAccessDenied
	}
	var currentScope GrantScope
	if err := json.Unmarshal(currentScopeJSON, &currentScope); err != nil {
		return CommandStatus{}, ErrDatabaseUnavailable
	}
	if !grantScopeSubset(ticket.Scope, currentScope) ||
		!scopeIncludesSession(ticket.Scope, sessionID, workspaceID) ||
		!scopeIncludesSession(currentScope, sessionID, workspaceID) {
		return CommandStatus{}, ErrAccessDenied
	}

	var check func(CommandStatus) error
	if admission != nil {
		check = func(status CommandStatus) error { return admission(ctx, transaction, status) }
	}
	return recordAuthorizedCommand(ctx, transaction, ticket, requestID, sessionID, "", payloadSHA256, orgID, commandType, postgres.commands.metrics, check)
}

func recordAuthorizedCommand(ctx context.Context, transaction *sql.Tx, ticket TicketRedemption, requestID, sessionID, workspaceID, payloadSHA256, orgID, action string, metrics *observability.Metrics, admission ...func(CommandStatus) error) (CommandStatus, error) {
	var status CommandStatus
	var existingUserID, existingRuntimeID string
	var existingAction sql.NullString
	err := transaction.QueryRowContext(ctx, `
		select request_id::text, user_id::text, runtime_id::text, coalesce(session_id::text, ''), coalesce(workspace_id::text, ''), state, payload_sha256, updated_at, action
		from commands where device_id = $1 and request_id = $2 for update`, ticket.DeviceID, requestID).
		Scan(&status.RequestID, &existingUserID, &existingRuntimeID, &status.SessionID, &status.WorkspaceID, &status.State, &status.PayloadSHA256, &status.UpdatedAt, &existingAction)
	if err == nil {
		if existingAction.Valid && existingAction.String != action || existingUserID != ticket.UserID || existingRuntimeID != ticket.RuntimeID || (workspaceID == "" && status.SessionID != sessionID) || status.WorkspaceID != workspaceID || status.PayloadSHA256 != payloadSHA256 {
			return CommandStatus{}, ErrCommandConflict
		}
		if len(admission) > 0 && admission[0] != nil {
			if err := admission[0](status); err != nil {
				return CommandStatus{}, err
			}
		}
		if err := transaction.Commit(); err != nil {
			return CommandStatus{}, ErrDatabaseUnavailable
		}
		return status, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return CommandStatus{}, ErrDatabaseUnavailable
	}

	err = transaction.QueryRowContext(ctx, `
		insert into commands (device_id, request_id, user_id, runtime_id, session_id, payload_sha256, workspace_id, state, action)
		values ($1, $2, $3, $4, nullif($5, '')::uuid, $6, nullif($7, '')::uuid, 'received', $8)
		on conflict (device_id, request_id) do nothing
		returning request_id::text, user_id::text, runtime_id::text, coalesce(session_id::text, ''), coalesce(workspace_id::text, ''), state, payload_sha256, updated_at, action`,
		ticket.DeviceID, requestID, ticket.UserID, ticket.RuntimeID, sessionID, payloadSHA256, workspaceID, action).
		Scan(&status.RequestID, &existingUserID, &existingRuntimeID, &status.SessionID, &status.WorkspaceID, &status.State, &status.PayloadSHA256, &status.UpdatedAt, &existingAction)
	inserted := err == nil
	if errors.Is(err, sql.ErrNoRows) {
		// A concurrent retry inserted the same primary key after the first lookup.
		err = transaction.QueryRowContext(ctx, `
			select request_id::text, user_id::text, runtime_id::text, coalesce(session_id::text, ''), coalesce(workspace_id::text, ''), state, payload_sha256, updated_at, action
			from commands where device_id = $1 and request_id = $2 for update`, ticket.DeviceID, requestID).
			Scan(&status.RequestID, &existingUserID, &existingRuntimeID, &status.SessionID, &status.WorkspaceID, &status.State, &status.PayloadSHA256, &status.UpdatedAt, &existingAction)
		if err == nil && (existingAction.Valid && existingAction.String != action || existingUserID != ticket.UserID || existingRuntimeID != ticket.RuntimeID || (workspaceID == "" && status.SessionID != sessionID) || status.WorkspaceID != workspaceID || status.PayloadSHA256 != payloadSHA256) {
			return CommandStatus{}, ErrCommandConflict
		}
	}
	if err != nil {
		return CommandStatus{}, ErrDatabaseUnavailable
	}
	if inserted {
		metadata, _ := json.Marshal(map[string]any{
			"request_id": requestID, "payload_sha256": payloadSHA256, "state": status.State, "workspace_id": workspaceID,
		})
		if _, err := transaction.ExecContext(ctx, `
			insert into audit_log (org_id, actor_type, actor_id, device_id, runtime_id, session_id, action, result, metadata)
			values ($1, 'device', $2::uuid::text, $2, $3, nullif($4, '')::uuid, 'command.received', 'success', $5::jsonb)`,
			orgID, ticket.DeviceID, ticket.RuntimeID, sessionID, string(metadata)); err != nil {
			return CommandStatus{}, ErrDatabaseUnavailable
		}
	}
	if len(admission) > 0 && admission[0] != nil {
		if err := admission[0](status); err != nil {
			return CommandStatus{}, err
		}
	}
	if err := transaction.Commit(); err != nil {
		return CommandStatus{}, ErrDatabaseUnavailable
	}
	if inserted {
		metrics.CommandTransition(action, "none", status.State, "device", status.UpdatedAt, time.Time{}, status.UpdatedAt)
	}
	return status, nil
}

// RecordRealtimeCommandReceipt accepts a receipt only from the current
// installation/runtime connection and enforces the command state machine.
func (postgres *Postgres) RecordRealtimeCommandReceipt(ctx context.Context, receipt RelayCommandReceipt) (CommandStatus, error) {
	started := time.Now()
	status, err := postgres.recordRealtimeCommandReceipt(ctx, receipt)
	postgres.observeCommandStore(ctx, "receipt", started, err)
	return status, err
}

func (postgres *Postgres) recordRealtimeCommandReceipt(ctx context.Context, receipt RelayCommandReceipt) (CommandStatus, error) {
	if !grantUUIDPattern.MatchString(receipt.InstallationID) || !grantUUIDPattern.MatchString(receipt.RuntimeID) ||
		!grantUUIDPattern.MatchString(receipt.RuntimeEpoch) || !grantUUIDPattern.MatchString(receipt.ConnectionID) ||
		!grantUUIDPattern.MatchString(receipt.DeviceID) || !grantUUIDPattern.MatchString(receipt.RequestID) ||
		receipt.KeyVersion <= 0 || !validSHA256Hex(receipt.PayloadSHA256) {
		return CommandStatus{}, ErrCommandTransition
	}
	if receipt.WorkspaceID == "" {
		if !grantUUIDPattern.MatchString(receipt.SessionID) || receipt.CreatedSession != nil {
			return CommandStatus{}, ErrCommandTransition
		}
	} else {
		if !grantUUIDPattern.MatchString(receipt.WorkspaceID) || receipt.State == "agent_queued" || receipt.State == "observed" {
			return CommandStatus{}, ErrCommandTransition
		}
		if receipt.State == "settled" {
			if err := validateCreatedSession(receipt); err != nil {
				return CommandStatus{}, err
			}
		} else if receipt.SessionID != "" || receipt.CreatedSession != nil {
			return CommandStatus{}, ErrCommandTransition
		}
	}
	if _, ok := relayReceiptStates[receipt.State]; !ok {
		return CommandStatus{}, ErrCommandTransition
	}
	transaction, err := postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return CommandStatus{}, ErrDatabaseUnavailable
	}
	defer transaction.Rollback()
	var orgID string
	err = transaction.QueryRowContext(ctx, `
		select h.org_id::text
		from runtimes r
		join installations i on i.id = r.installation_id and i.revoked_at is null
		join hosts h on h.id = i.host_id and h.state = 'active'
		where r.id = $1 and i.id = $2 and i.key_version = $3 and r.epoch = $4
		  and r.connection_id = $5 and r.revoked_at is null and `+runtimeEnrollmentApprovedSQL+`
		for share of r, i, h`, receipt.RuntimeID, receipt.InstallationID, receipt.KeyVersion,
		receipt.RuntimeEpoch, receipt.ConnectionID).Scan(&orgID)
	if errors.Is(err, sql.ErrNoRows) {
		return CommandStatus{}, ErrRuntimeConnectionStale
	}
	if err != nil {
		return CommandStatus{}, ErrDatabaseUnavailable
	}
	var status CommandStatus
	var action sql.NullString
	var created time.Time
	err = transaction.QueryRowContext(ctx, `
		select c.request_id::text, coalesce(c.session_id::text, ''), coalesce(c.workspace_id::text, ''), c.state, c.payload_sha256, c.updated_at,c.action,c.created_at
		from commands c
		where c.device_id = $1 and c.request_id = $2 and c.runtime_id = $3
		for update`, receipt.DeviceID, receipt.RequestID, receipt.RuntimeID).
		Scan(&status.RequestID, &status.SessionID, &status.WorkspaceID, &status.State, &status.PayloadSHA256, &status.UpdatedAt, &action, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return CommandStatus{}, ErrCommandTransition
	}
	if err != nil {
		return CommandStatus{}, ErrDatabaseUnavailable
	}
	if status.WorkspaceID != receipt.WorkspaceID || status.PayloadSHA256 != receipt.PayloadSHA256 ||
		(status.WorkspaceID == "" && status.SessionID != receipt.SessionID) ||
		(status.WorkspaceID != "" && status.SessionID != "" && status.SessionID != receipt.SessionID) {
		return CommandStatus{}, ErrCommandConflict
	}
	if status.State == receipt.State {
		if err := transaction.Commit(); err != nil {
			return CommandStatus{}, ErrDatabaseUnavailable
		}
		return status, nil
	}
	if _, ok := commandTransitions[status.State][receipt.State]; !ok {
		return CommandStatus{}, ErrCommandTransition
	}
	if receipt.CreatedSession != nil {
		if err := recordCreatedSession(ctx, transaction, receipt); err != nil {
			return CommandStatus{}, err
		}
		status.SessionID = receipt.SessionID
	}
	previousState, previousEntered := status.State, status.UpdatedAt
	err = transaction.QueryRowContext(ctx, `
		update commands set state = $1, session_id = nullif($4, '')::uuid, updated_at = clock_timestamp()
		where device_id = $2 and request_id = $3
		returning updated_at`, receipt.State, receipt.DeviceID, receipt.RequestID, status.SessionID).Scan(&status.UpdatedAt)
	if err != nil {
		return CommandStatus{}, ErrDatabaseUnavailable
	}
	status.State = receipt.State
	metadata, _ := json.Marshal(map[string]any{
		"request_id": receipt.RequestID, "payload_sha256": receipt.PayloadSHA256, "state": receipt.State,
		"device_id": receipt.DeviceID,
	})
	if _, err := transaction.ExecContext(ctx, `
		insert into audit_log (org_id, actor_type, actor_id, runtime_id, session_id, action, result, metadata)
		values ($1, 'installation', $2, $3, nullif($4, '')::uuid, 'command.receipt', 'success', $5::jsonb)`,
		orgID, receipt.InstallationID, receipt.RuntimeID, receipt.SessionID, string(metadata)); err != nil {
		return CommandStatus{}, ErrDatabaseUnavailable
	}
	if err := transaction.Commit(); err != nil {
		return CommandStatus{}, ErrDatabaseUnavailable
	}
	postgres.commands.metrics.CommandTransition(action.String, previousState, status.State, "host", created, previousEntered, status.UpdatedAt)
	return status, nil
}

// MarkRealtimeCommandUnknown records uncertainty after a host socket write
// fails after dispatch began. A later host receipt can still resolve it only
// through an explicit recovery path, never by silently replaying the body.
func (postgres *Postgres) MarkRealtimeCommandUnknown(ctx context.Context, ticket TicketRedemption, requestID, sessionID, payloadSHA256 string) (CommandStatus, error) {
	started := time.Now()
	status, err := postgres.markRealtimeCommandUnknown(ctx, ticket, requestID, sessionID, payloadSHA256)
	postgres.observeCommandStore(ctx, "unknown", started, err)
	return status, err
}

func (postgres *Postgres) markRealtimeCommandUnknown(ctx context.Context, ticket TicketRedemption, requestID, sessionID, payloadSHA256 string) (CommandStatus, error) {
	if !grantUUIDPattern.MatchString(ticket.UserID) || !grantUUIDPattern.MatchString(ticket.DeviceID) ||
		!grantUUIDPattern.MatchString(ticket.RuntimeID) || !grantUUIDPattern.MatchString(requestID) ||
		(sessionID != "" && !grantUUIDPattern.MatchString(sessionID)) || !validSHA256Hex(payloadSHA256) {
		return CommandStatus{}, ErrCommandTransition
	}
	transaction, err := postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return CommandStatus{}, ErrDatabaseUnavailable
	}
	defer transaction.Rollback()
	var status CommandStatus
	var action sql.NullString
	var created time.Time
	err = transaction.QueryRowContext(ctx, `
		select c.request_id::text, coalesce(c.session_id::text, ''), coalesce(c.workspace_id::text, ''), c.state, c.payload_sha256, c.updated_at,c.action,c.created_at
		from commands c
		where c.device_id = $1 and c.user_id = $2 and c.request_id = $3 and c.runtime_id = $4
		for update`, ticket.DeviceID, ticket.UserID, requestID, ticket.RuntimeID).
		Scan(&status.RequestID, &status.SessionID, &status.WorkspaceID, &status.State, &status.PayloadSHA256, &status.UpdatedAt, &action, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return CommandStatus{}, ErrCommandTransition
	}
	if err != nil {
		return CommandStatus{}, ErrDatabaseUnavailable
	}
	if status.SessionID != sessionID || status.PayloadSHA256 != payloadSHA256 {
		return CommandStatus{}, ErrCommandConflict
	}
	if status.State != "received" {
		if err := transaction.Commit(); err != nil {
			return CommandStatus{}, ErrDatabaseUnavailable
		}
		return status, nil
	}
	previousEntered := status.UpdatedAt
	err = transaction.QueryRowContext(ctx, `
		update commands set state = 'outcome_unknown', updated_at = clock_timestamp()
		where device_id = $1 and request_id = $2 returning updated_at`, ticket.DeviceID, requestID).Scan(&status.UpdatedAt)
	if err != nil {
		return CommandStatus{}, ErrDatabaseUnavailable
	}
	status.State = "outcome_unknown"
	metadata, _ := json.Marshal(map[string]any{"request_id": requestID, "payload_sha256": payloadSHA256, "state": status.State})
	if _, err := transaction.ExecContext(ctx, `
		insert into audit_log (actor_type, actor_id, device_id, runtime_id, session_id, action, result, metadata)
		values ('device', $1::uuid::text, $1, $2, nullif($3, '')::uuid, 'command.outcome_unknown', 'unknown', $4::jsonb)`,
		ticket.DeviceID, ticket.RuntimeID, sessionID, string(metadata)); err != nil {
		return CommandStatus{}, ErrDatabaseUnavailable
	}
	if err := transaction.Commit(); err != nil {
		return CommandStatus{}, ErrDatabaseUnavailable
	}
	postgres.commands.metrics.CommandTransition(action.String, "received", status.State, "relay", created, previousEntered, status.UpdatedAt)
	return status, nil
}

func validSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func scopeIncludesSession(scope GrantScope, sessionID string, workspaceID sql.NullString) bool {
	if slices.Contains(scope.Sessions, sessionID) {
		return true
	}
	return workspaceID.Valid && slices.Contains(scope.Workspaces, workspaceID.String)
}
