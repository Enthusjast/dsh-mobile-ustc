package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"dsh-mobile-ustc/services/remote/internal/canonical"
)

// SessionForkOutcome describes independently recoverable effects of one native fork.
// The source command identity never changes when a child has been created.
type SessionForkOutcome struct {
	Version             int    `json:"v"`
	WorkspaceAttachment string `json:"workspace_attachment"`
	Checkpoint          string `json:"checkpoint"`
}

func (outcome *SessionForkOutcome) valid() bool {
	return outcome != nil && outcome.Version == 1 &&
		slices.Contains([]string{"attached", "failed", "unknown"}, outcome.WorkspaceAttachment) &&
		slices.Contains([]string{"persisted", "unavailable", "failed", "unknown"}, outcome.Checkpoint)
}

// DecodeSessionForkOutcome accepts only the complete, unambiguous v1 object.
// A nil database value means no fork evidence has been recorded yet.
func DecodeSessionForkOutcome(raw []byte) (*SessionForkOutcome, error) {
	if raw == nil {
		return nil, nil
	}
	if len(raw) > 1024 {
		return nil, ErrCommandTransition
	}
	if _, err := canonical.Object(raw); err != nil {
		return nil, ErrCommandTransition
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 3 || fields["v"] == nil || fields["workspace_attachment"] == nil || fields["checkpoint"] == nil {
		return nil, ErrCommandTransition
	}
	var outcome SessionForkOutcome
	if json.Unmarshal(raw, &outcome) != nil || !outcome.valid() {
		return nil, ErrCommandTransition
	}
	return &outcome, nil
}

func validSessionForkTarget(ticket TicketRedemption, sourceSessionID, workspaceID string) bool {
	return grantUUIDPattern.MatchString(ticket.UserID) && grantUUIDPattern.MatchString(ticket.DeviceID) &&
		grantUUIDPattern.MatchString(ticket.RuntimeID) && grantUUIDPattern.MatchString(sourceSessionID) &&
		grantUUIDPattern.MatchString(workspaceID)
}

// AuthorizeRealtimeSessionFork rechecks current source, workspace and grant rows
// immediately before dispatch. Authorization is not a replay permission.
func (postgres *Postgres) AuthorizeRealtimeSessionFork(ctx context.Context, ticket TicketRedemption, sourceSessionID, workspaceID string) error {
	if !validSessionForkTarget(ticket, sourceSessionID, workspaceID) {
		return ErrAccessDenied
	}
	tx, err := postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	if _, err := authorizeSessionForkResources(ctx, tx, ticket, sourceSessionID, workspaceID); err != nil {
		return err
	}
	if err := checkCommandGrantTime(ctx, tx, ticket); err != nil {
		return err
	}
	if tx.Commit() != nil {
		return ErrDatabaseUnavailable
	}
	return nil
}

// RecordRealtimeSessionFork stores only the original source identity and digest.
// Forks consume the existing workspace session.create budget, not a new policy.
func (postgres *Postgres) RecordRealtimeSessionFork(ctx context.Context, ticket TicketRedemption, requestID, sourceSessionID, workspaceID, digest string) (CommandStatus, error) {
	started := time.Now()
	status, err := postgres.recordRealtimeSessionFork(ctx, ticket, requestID, sourceSessionID, workspaceID, digest)
	postgres.observeCommandStore(ctx, "fork", started, err)
	return status, err
}

func (postgres *Postgres) recordRealtimeSessionFork(ctx context.Context, ticket TicketRedemption, requestID, sourceSessionID, workspaceID, digest string) (CommandStatus, error) {
	if !validSessionForkTarget(ticket, sourceSessionID, workspaceID) || !grantUUIDPattern.MatchString(requestID) || !validSHA256Hex(digest) {
		return CommandStatus{}, ErrGrantInvalid
	}
	if err := postgres.AuthorizeRealtimeSessionFork(ctx, ticket, sourceSessionID, workspaceID); err != nil {
		return CommandStatus{}, err
	}
	if err := postgres.admitCommandRate(ctx, ticket, "session.create", "", workspaceID, false); err != nil {
		return CommandStatus{}, err
	}
	tx, err := postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return CommandStatus{}, ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	authority, err := authorizeSessionForkResources(ctx, tx, ticket, sourceSessionID, workspaceID)
	if err != nil {
		return CommandStatus{}, err
	}
	return recordAuthorizedCommand(ctx, tx, ticket, requestID, sourceSessionID, workspaceID, digest, authority.organization, "session.fork", postgres.commands.metrics)
}

func validateSessionForkReceipt(ctx context.Context, tx *sql.Tx, receipt RelayCommandReceipt) error {
	if receipt.CommandType != "session.fork" || !grantUUIDPattern.MatchString(receipt.SessionID) || !grantUUIDPattern.MatchString(receipt.WorkspaceID) ||
		receipt.State == "agent_queued" || receipt.State == "observed" ||
		(receipt.ChildSessionID != "" && (!grantUUIDPattern.MatchString(receipt.ChildSessionID) || receipt.ChildSessionID == receipt.SessionID)) ||
		(receipt.ForkOutcome != nil && !receipt.ForkOutcome.valid()) {
		return ErrCommandTransition
	}
	if receipt.ForkOutcome != nil && receipt.ForkOutcome.Checkpoint == "persisted" {
		if receipt.ChildSessionID == "" {
			return ErrCommandTransition
		}
	} else if receipt.CreatedSession != nil {
		return ErrCommandTransition
	}
	if receipt.State == "settled" && (receipt.ChildSessionID == "" || receipt.ForkOutcome == nil || receipt.ForkOutcome.Checkpoint != "persisted" || receipt.CreatedSession == nil) {
		return ErrCommandTransition
	}
	var sourceWorkspace string
	err := tx.QueryRowContext(ctx, `select w.id::text from sessions s
	 join workspaces w on w.runtime_id=s.runtime_id and w.id=s.workspace_id
	 where s.runtime_id=$1 and s.id=$2 and w.id=$3 for share of s,w`, receipt.RuntimeID, receipt.SessionID, receipt.WorkspaceID).Scan(&sourceWorkspace)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrCommandConflict
	}
	if err != nil {
		return ErrDatabaseUnavailable
	}
	if receipt.CreatedSession != nil {
		childReceipt := receipt
		childReceipt.SessionID = receipt.ChildSessionID
		if err := validateCreatedSession(childReceipt); err != nil {
			return err
		}
	}
	if receipt.ChildSessionID != "" {
		var runtimeID string
		var workspaceID sql.NullString
		err := tx.QueryRowContext(ctx, `select runtime_id::text,workspace_id::text from sessions where id=$1 for share`, receipt.ChildSessionID).Scan(&runtimeID, &workspaceID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return ErrDatabaseUnavailable
		}
		requiresWorkspace := receipt.CreatedSession != nil || receipt.ForkOutcome != nil && receipt.ForkOutcome.WorkspaceAttachment == "attached"
		if err == nil && (runtimeID != receipt.RuntimeID || requiresWorkspace && (!workspaceID.Valid || workspaceID.String != receipt.WorkspaceID)) {
			return ErrCommandConflict
		}
	}
	return nil
}

// Sparse uncertainty receipts retain known child identity and positive evidence.
// Only unknown/failed evidence may advance; persisted/attached cannot regress.
func mergeSessionForkReceipt(status *CommandStatus, receipt RelayCommandReceipt) error {
	if receipt.ChildSessionID != "" {
		if status.ChildSessionID != "" && status.ChildSessionID != receipt.ChildSessionID {
			return ErrCommandConflict
		}
		status.ChildSessionID = receipt.ChildSessionID
	}
	if receipt.ForkOutcome == nil {
		return nil
	}
	merged := *receipt.ForkOutcome
	if status.ForkOutcome != nil {
		previous := status.ForkOutcome
		if merged.WorkspaceAttachment == "unknown" {
			merged.WorkspaceAttachment = previous.WorkspaceAttachment
		} else if previous.WorkspaceAttachment == "attached" && merged.WorkspaceAttachment != "attached" {
			return ErrCommandConflict
		}
		if merged.Checkpoint == "unknown" {
			merged.Checkpoint = previous.Checkpoint
		} else if previous.Checkpoint != "unknown" && merged.Checkpoint != previous.Checkpoint && merged.Checkpoint != "persisted" {
			return ErrCommandConflict
		}
	}
	status.ForkOutcome = &merged
	return nil
}
