package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"time"
)

type QuestionReferenceStatus struct {
	ID, Kind, State, RuntimeID, RuntimeEpoch, SessionID, Availability string
	ValidUntil                                                        time.Time
}

// A current grant permits reading metadata, never answering from that metadata.
// The caller must still read and answer the current native question over Relay.
func (postgres *Postgres) AuthorizeQuestionReference(ctx context.Context, ticket TicketRedemption, id string) (QuestionReferenceStatus, error) {
	var status QuestionReferenceStatus
	if !grantUUIDPattern.MatchString(id) || !grantUUIDPattern.MatchString(ticket.RuntimeID) || !grantUUIDPattern.MatchString(ticket.UserID) ||
		!grantUUIDPattern.MatchString(ticket.DeviceID) || !slices.Contains(ticket.Scope.Actions, "session.read") || !slices.Contains(ticket.Scope.Actions, "question.answer") {
		return status, ErrAccessDenied
	}
	var nativeExpiry, seen, lease, updated sql.NullTime
	var sourceConnection, epoch, connection, feedEpoch, feedConnection sql.NullString
	var runtimeKey, feedKey sql.NullInt64
	var scopeJSON []byte
	var workspace sql.NullString
	var sessionState string
	err := postgres.DB.QueryRowContext(ctx, `select q.id::text,q.kind,q.state,q.runtime_id::text,q.runtime_epoch::text,q.session_id::text,q.connection_id::text,q.expires_at,
	 r.epoch::text,r.connection_id::text,r.last_seen_at,r.connection_key_version,f.runtime_epoch::text,f.connection_id::text,f.key_version,f.lease_until,f.updated_at,
	 g.scope,s.workspace_id::text,s.state
	 from question_references q join runtimes r on r.id=q.runtime_id and r.revoked_at is null and `+runtimeEnrollmentApprovedSQL+`
	 join installations i on i.id=r.installation_id and i.revoked_at is null join hosts h on h.id=i.host_id and h.state='active'
	 join org_memberships m on m.org_id=h.org_id and m.user_id=$3 join users u on u.id=m.user_id and u.status='active'
	 join devices d on d.user_id=u.id and d.id=$4 and d.revoked_at is null and d.key_version=$5 and d.proof_key_thumbprint=$6
	 join runtime_grants g on g.runtime_id=r.id and g.user_id=u.id and g.grant_version=$7 and g.role in ('owner','operator')
	 and g.revoked_at is null and (g.expires_at is null or g.expires_at>clock_timestamp())
	 join sessions s on s.id=q.session_id and s.runtime_id=r.id left join question_reference_feeds f on f.runtime_id=q.runtime_id
	 where q.id=$1 and q.runtime_id=$2`, id, ticket.RuntimeID, ticket.UserID, ticket.DeviceID, ticket.DeviceKeyVersion, ticket.ProofKeyThumbprint, ticket.GrantVersion).Scan(&status.ID, &status.Kind, &status.State, &status.RuntimeID, &status.RuntimeEpoch, &status.SessionID, &sourceConnection, &nativeExpiry,
		&epoch, &connection, &seen, &runtimeKey, &feedEpoch, &feedConnection, &feedKey, &lease, &updated, &scopeJSON, &workspace, &sessionState)
	if errors.Is(err, sql.ErrNoRows) {
		return status, ErrAccessDenied
	}
	if err != nil {
		return status, ErrDatabaseUnavailable
	}
	var scope GrantScope
	if json.Unmarshal(scopeJSON, &scope) != nil {
		return status, ErrDatabaseUnavailable
	}
	if !grantScopeSubset(ticket.Scope, scope) || !scopeIncludesSession(ticket.Scope, status.SessionID, workspace) || !scopeIncludesSession(scope, status.SessionID, workspace) {
		return status, ErrAccessDenied
	}
	now := time.Now()
	status.ValidUntil = lease.Time
	if status.Kind == "question" && nativeExpiry.Valid && nativeExpiry.Time.Before(status.ValidUntil) {
		status.ValidUntil = nativeExpiry.Time
	}
	switch {
	case epoch.String != status.RuntimeEpoch:
		status.Availability = "stale_epoch"
	case status.State == "ended" || sessionState == "archived":
		status.State = "ended"
		status.Availability = "ended"
	case status.Kind == "question" && (!nativeExpiry.Valid || !nativeExpiry.Time.After(now)):
		status.State = "expired"
		status.Availability = "ended"
	case !connection.Valid || !seen.Valid || seen.Time.After(now) || now.Sub(seen.Time) > 45*time.Second:
		status.Availability = "host_offline"
	case connection.String != sourceConnection.String || feedEpoch.String != status.RuntimeEpoch || feedConnection.String != sourceConnection.String ||
		sessionState == "unavailable" ||
		!runtimeKey.Valid || !feedKey.Valid || runtimeKey.Int64 != feedKey.Int64 || !lease.Valid || !updated.Valid || updated.Time.After(now) || !lease.Time.After(now) ||
		status.Kind == "timed_question" && status.State == "pending" && nativeExpiry.Valid && !nativeExpiry.Time.After(now):
		status.Availability = "state_unavailable"
	default:
		status.Availability = "online"
	}
	return status, nil
}
