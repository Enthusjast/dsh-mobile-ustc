package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
)

// AuthorizeRealtimeSessionRead is called at admission and before every content
// frame. Directory visibility alone never grants access to session bodies.
func (postgres *Postgres) AuthorizeRealtimeSessionRead(ctx context.Context, ticket TicketRedemption, sessionID string) error {
	if !grantUUIDPattern.MatchString(sessionID) || !slices.Contains(ticket.Scope.Actions, "session.read") {
		return ErrAccessDenied
	}
	var scopeJSON []byte
	var workspaceID sql.NullString
	var state string
	err := postgres.DB.QueryRowContext(ctx, `
		select g.scope, s.workspace_id::text, s.state
		from users u
		join devices d on d.user_id = u.id and d.id = $2 and d.revoked_at is null
		join org_memberships m on m.user_id = u.id
		join hosts h on h.org_id = m.org_id and h.state = 'active'
		join installations i on i.host_id = h.id and i.revoked_at is null
		join runtimes r on r.installation_id = i.id and r.id = $3 and r.revoked_at is null
		join runtime_grants g on g.runtime_id = r.id and g.user_id = u.id and g.grant_version = $4
		join sessions s on s.runtime_id = r.id and s.id = $5
		where u.id = $1 and u.status = 'active' and d.key_version = $6 and d.proof_key_thumbprint = $7
		  and g.revoked_at is null and (g.expires_at is null or g.expires_at > clock_timestamp())`,
		ticket.UserID, ticket.DeviceID, ticket.RuntimeID, ticket.GrantVersion, sessionID,
		ticket.DeviceKeyVersion, ticket.ProofKeyThumbprint).Scan(&scopeJSON, &workspaceID, &state)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrAccessDenied
	}
	if err != nil {
		return ErrDatabaseUnavailable
	}
	var scope GrantScope
	if json.Unmarshal(scopeJSON, &scope) != nil {
		return ErrDatabaseUnavailable
	}
	if state == "unavailable" || !grantScopeSubset(ticket.Scope, scope) ||
		!scopeIncludesSession(ticket.Scope, sessionID, workspaceID) || !scopeIncludesSession(scope, sessionID, workspaceID) {
		return ErrAccessDenied
	}
	return nil
}
