package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// SessionReadAccess authorizes a bounded local history view, not a bearer
// credential, a live subscription, or access to any other session.
type SessionReadAccess struct {
	RuntimeID    string    `json:"runtime_id"`
	SessionID    string    `json:"session_id"`
	WorkspaceID  *string   `json:"workspace_id"`
	GrantVersion int64     `json:"grant_version"`
	IssuedAt     time.Time `json:"issued_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

func (postgres *Postgres) SessionCacheReadAccess(ctx context.Context, identity UserIdentity, deviceID, proofJKT, runtimeID, sessionID string, credentialUntil time.Time) (SessionReadAccess, error) {
	if !grantUUIDPattern.MatchString(deviceID) || !grantUUIDPattern.MatchString(runtimeID) || !grantUUIDPattern.MatchString(sessionID) {
		return SessionReadAccess{}, ErrAccessDenied
	}
	result := SessionReadAccess{RuntimeID: runtimeID, SessionID: sessionID}
	// Unavailable host content can still have authorized local history. Check
	// current read permission and membership atomically without serving a body.
	err := postgres.DB.QueryRowContext(ctx, `
		select s.workspace_id::text, g.grant_version, statement_timestamp(),
		       least(statement_timestamp() + interval '5 minutes', g.expires_at, $7::timestamptz)
		from users u
		join devices d on d.user_id=u.id and d.id=$3 and d.revoked_at is null and d.proof_key_thumbprint=$4
		join org_memberships m on m.user_id=u.id
		join hosts h on h.org_id=m.org_id and h.state='active'
		join installations i on i.host_id=h.id and i.revoked_at is null
		join runtimes r on r.installation_id=i.id and r.id=$5 and r.revoked_at is null and `+runtimeEnrollmentApprovedSQL+`
		join runtime_grants g on g.runtime_id=r.id and g.user_id=u.id
		join sessions s on s.runtime_id=r.id and s.id=$6
		where u.issuer=$1 and u.subject=$2 and u.status='active'
		  and g.revoked_at is null and (g.expires_at is null or g.expires_at > clock_timestamp())
		  and $7::timestamptz > clock_timestamp() and g.scope->'actions' ? 'session.read'
		  and (coalesce(g.scope->'sessions','[]'::jsonb) @> jsonb_build_array(s.id::text)
		    or (s.workspace_id is not null and coalesce(g.scope->'workspaces','[]'::jsonb) @> jsonb_build_array(s.workspace_id::text)))`,
		identity.Issuer, identity.Subject, deviceID, proofJKT, runtimeID, sessionID, credentialUntil).
		Scan(&result.WorkspaceID, &result.GrantVersion, &result.IssuedAt, &result.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return SessionReadAccess{}, ErrAccessDenied
	}
	if err != nil {
		return SessionReadAccess{}, ErrDatabaseUnavailable
	}
	if !result.ExpiresAt.After(time.Now()) {
		return SessionReadAccess{}, ErrAccessDenied
	}
	return result, nil
}
