package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
)

// AuthorizeView guards approval details/status delivery with both the current
// owner approval authority and the admitted socket's explicit content scope.
// It supplies no authentication assurance or execution permission.
func (control *ApprovalControl) AuthorizeView(ctx context.Context, ticket TicketRedemption, approvalID string) (ApprovalStatus, error) {
	return control.authorizeRead(ctx, ticket, approvalID, true)
}

// Status metadata remains readable after host disconnection; full details need
// the original current connection and catalog mapping in AuthorizeView.
func (control *ApprovalControl) AuthorizeStatus(ctx context.Context, ticket TicketRedemption, approvalID string) (ApprovalStatus, error) {
	return control.authorizeRead(ctx, ticket, approvalID, false)
}

func validApprovalRead(ticket TicketRedemption, approvalID string) bool {
	if !grantUUIDPattern.MatchString(approvalID) || !grantUUIDPattern.MatchString(ticket.UserID) || !grantUUIDPattern.MatchString(ticket.DeviceID) || !grantUUIDPattern.MatchString(ticket.RuntimeID) ||
		ticket.DeviceKeyVersion < 1 || ticket.GrantVersion < 1 || !slices.Contains(ticket.Scope.Actions, "approval.decide") || !slices.Contains(ticket.Scope.Actions, "session.read") {
		return false
	}
	_, err := NormalizeTicketScope("owner", ticket.Scope)
	return err == nil
}

func (control *ApprovalControl) authorizeRead(ctx context.Context, ticket TicketRedemption, approvalID string, details bool) (ApprovalStatus, error) {
	if !validApprovalRead(ticket, approvalID) {
		return ApprovalStatus{}, ErrAccessDenied
	}
	ctx, cancel := context.WithTimeout(ctx, approvalAdmissionTimeout)
	defer cancel()
	transaction, err := control.database.DB.BeginTx(ctx, nil)
	if err != nil {
		return ApprovalStatus{}, ErrDatabaseUnavailable
	}
	defer transaction.Rollback()
	status, err := authorizeApprovalRead(ctx, transaction, ticket, approvalID, details)
	if err != nil {
		return ApprovalStatus{}, err
	}
	if err := transaction.Commit(); err != nil {
		return ApprovalStatus{}, ErrDatabaseUnavailable
	}
	return status, nil
}

// Shared current-owner read policy for both admitted WSS scopes and HTTP proof
// resolution. Callers own the transaction and commit only after these checks.
func authorizeApprovalRead(ctx context.Context, transaction *sql.Tx, ticket TicketRedemption, approvalID string, details bool) (ApprovalStatus, error) {
	if !validApprovalRead(ticket, approvalID) {
		return ApprovalStatus{}, ErrAccessDenied
	}
	var scopeJSON []byte
	var workspace sql.NullString
	var sessionID string
	var grantExpiry sql.NullTime
	err := transaction.QueryRowContext(ctx, `
		select g.scope, a.workspace_id::text, s.id::text, g.expires_at
		from approvals a
		join sessions s on s.id = a.session_id and s.runtime_id = a.runtime_id
		join runtimes r on r.id = s.runtime_id and r.revoked_at is null and `+runtimeEnrollmentApprovedSQL+`
		join installations i on i.id = r.installation_id and i.revoked_at is null
		join hosts h on h.id = i.host_id and h.state = 'active'
		join org_memberships m on m.org_id = h.org_id and m.user_id = $2
		join users u on u.id = m.user_id and u.status = 'active'
		join devices d on d.user_id = u.id and d.id = $3 and d.revoked_at is null
		join runtime_grants g on g.runtime_id = r.id and g.user_id = u.id
		where a.id = $1 and a.metadata_version = 1 and r.id = $4
		  and d.key_version = $5 and d.proof_key_thumbprint = $6
		  and g.grant_version = $7 and g.role = 'owner' and g.revoked_at is null
		  and (g.expires_at is null or g.expires_at > clock_timestamp())
		  and (not $8 or (s.state in ('available', 'running') and s.workspace_id = a.workspace_id
		      and r.epoch = a.runtime_epoch and r.connection_id = a.connection_id and r.connection_key_version = i.key_version
		      and r.last_seen_at > clock_timestamp() - interval '45 seconds'))
		for share of s, r, i, h, m, u, d, g`, approvalID, ticket.UserID, ticket.DeviceID, ticket.RuntimeID,
		ticket.DeviceKeyVersion, ticket.ProofKeyThumbprint, ticket.GrantVersion, details).
		Scan(&scopeJSON, &workspace, &sessionID, &grantExpiry)
	if errors.Is(err, sql.ErrNoRows) {
		return ApprovalStatus{}, ErrAccessDenied
	}
	if err != nil {
		return ApprovalStatus{}, ErrDatabaseUnavailable
	}
	var scope GrantScope
	if json.Unmarshal(scopeJSON, &scope) != nil {
		return ApprovalStatus{}, ErrDatabaseUnavailable
	}
	if !slices.Contains(scope.Actions, "approval.decide") || !slices.Contains(scope.Actions, "session.read") ||
		!grantScopeSubset(ticket.Scope, scope) || !scopeIncludesSession(scope, sessionID, workspace) || !scopeIncludesSession(ticket.Scope, sessionID, workspace) {
		return ApprovalStatus{}, ErrAccessDenied
	}
	status, _, err := readApproval(ctx, transaction, approvalID)
	if err != nil {
		return ApprovalStatus{}, ErrDatabaseUnavailable
	}
	now, err := approvalDatabaseTime(ctx, transaction)
	if err != nil {
		return ApprovalStatus{}, err
	}
	if grantExpiry.Valid && !grantExpiry.Time.After(now) {
		return ApprovalStatus{}, ErrAccessDenied
	}
	return status, nil
}

func (control *ApprovalControl) ListPending(ctx context.Context, ticket TicketRedemption) ([]ApprovalStatus, error) {
	if !grantUUIDPattern.MatchString(ticket.RuntimeID) || !slices.Contains(ticket.Scope.Actions, "approval.decide") || !slices.Contains(ticket.Scope.Actions, "session.read") {
		return nil, ErrAccessDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 2*approvalAdmissionTimeout)
	defer cancel()
	rows, err := control.database.DB.QueryContext(ctx, `
		select a.id::text from approvals a join runtimes r on r.id = a.runtime_id
		where a.runtime_id = $1 and a.metadata_version = 1 and a.runtime_epoch = r.epoch and a.connection_id = r.connection_id
		  and a.state in ('pending', 'decision_received') and a.expires_at > clock_timestamp()
		order by a.created_at, a.id limit 64`, ticket.RuntimeID)
	if err != nil {
		return nil, ErrDatabaseUnavailable
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, ErrDatabaseUnavailable
		}
		ids = append(ids, id)
	}
	readErr, closeErr := rows.Err(), rows.Close()
	if readErr != nil || closeErr != nil {
		return nil, ErrDatabaseUnavailable
	}
	statuses := []ApprovalStatus{}
	for _, id := range ids {
		status, err := control.AuthorizeView(ctx, ticket, id)
		if errors.Is(err, ErrAccessDenied) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if status.State == "pending" || status.State == "decision_received" {
			statuses = append(statuses, status)
		}
	}
	return statuses, nil
}
