package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// SessionTarget describes one already-known readable resource and the caller's
// own current grant. It grants neither directory enumeration nor live access.
type SessionTarget struct {
	Runtime Runtime `json:"runtime"`
	Session Session `json:"session"`
}

func (postgres *Postgres) SessionReadTarget(ctx context.Context, identity UserIdentity, device, proof, runtime, session string, credentialUntil time.Time) (SessionTarget, error) {
	var result SessionTarget
	if !grantUUIDPattern.MatchString(device) || !grantUUIDPattern.MatchString(runtime) || !grantUUIDPattern.MatchString(session) {
		return result, ErrAccessDenied
	}
	var access RuntimeAccess
	var raw []byte
	err := postgres.DB.QueryRowContext(ctx, `select r.id::text,h.id::text,h.org_id::text,coalesce(r.dsh_version,''),coalesce(r.application_version,''),coalesce(r.plugin_version,''),coalesce(r.protocol_version,0),r.last_seen_at,
	 g.role,g.grant_version,g.scope,g.expires_at,s.id::text,s.workspace_id::text,s.state,s.last_persisted_seq,s.updated_at
	 from users u join devices d on d.user_id=u.id and d.id=$3 and d.revoked_at is null and d.proof_key_thumbprint=$4
	 join org_memberships m on m.user_id=u.id join hosts h on h.org_id=m.org_id and h.state='active'
	 join installations i on i.host_id=h.id and i.revoked_at is null
	 join runtimes r on r.installation_id=i.id and r.id=$5 and r.revoked_at is null and `+runtimeEnrollmentApprovedSQL+`
	 join runtime_grants g on g.runtime_id=r.id and g.user_id=u.id
	 join sessions s on s.runtime_id=r.id and s.id=$6
	 where u.issuer=$1 and u.subject=$2 and u.status='active' and $7::timestamptz>clock_timestamp()
	 and g.revoked_at is null and (g.expires_at is null or g.expires_at>clock_timestamp()) and g.scope->'actions' ? 'session.read'
	 and (g.scope->'sessions' ? s.id::text or s.workspace_id is not null and g.scope->'workspaces' ? s.workspace_id::text)`,
		identity.Issuer, identity.Subject, device, proof, runtime, session, credentialUntil).Scan(&result.Runtime.ID, &result.Runtime.HostID, &result.Runtime.OrganizationID,
		&result.Runtime.DSHVersion, &result.Runtime.ApplicationVersion, &result.Runtime.PluginVersion, &result.Runtime.ProtocolVersion, &result.Runtime.LastSeenAt,
		&access.Role, &access.GrantVersion, &raw, &access.ExpiresAt, &result.Session.ID, &result.Session.WorkspaceID, &result.Session.State, &result.Session.LastPersistedSeq, &result.Session.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return result, ErrAccessDenied
	}
	if err != nil || json.Unmarshal(raw, &access.Scope) != nil {
		return result, ErrDatabaseUnavailable
	}
	result.Runtime.Access = &access
	result.Session.RuntimeID = result.Runtime.ID
	return result, nil
}
