package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
)

type commandAuthority struct{ organization, installation string }

// Shared by the quota attempt and the command transaction. A quota never acts
// as an authorization lease; the command transaction repeats these checks.
func authorizeCommandResources(ctx context.Context, tx *sql.Tx, ticket TicketRedemption, action, sessionID, workspaceID string, files bool) (commandAuthority, error) {
	var result commandAuthority
	var scopeJSON []byte
	var workspace sql.NullString
	var state string
	target, alias, projection := sessionID, "s", "s.workspace_id::text, s.state"
	join := `join sessions s on s.runtime_id = r.id and s.id = $5`
	if workspaceID != "" {
		target, alias, projection = workspaceID, "w", "w.id::text, 'available'::text"
		join = `join workspaces w on w.runtime_id = r.id and w.id = $5`
	}
	err := tx.QueryRowContext(ctx, `
		select g.scope, `+projection+`, h.org_id::text, i.id::text
		from users u
		join devices d on d.user_id = u.id and d.id = $2 and d.revoked_at is null
		join org_memberships m on m.user_id = u.id
		join hosts h on h.org_id = m.org_id and h.state = 'active'
		join installations i on i.host_id = h.id and i.revoked_at is null
		join runtimes r on r.installation_id = i.id and r.id = $3 and r.revoked_at is null and `+runtimeEnrollmentApprovedSQL+`
		join runtime_grants g on g.runtime_id = r.id and g.user_id = u.id and g.grant_version = $4
		`+join+`
		where u.id = $1 and u.status = 'active' and d.key_version = $6 and d.proof_key_thumbprint = $7
		  and g.revoked_at is null and (g.expires_at is null or g.expires_at > clock_timestamp())
		for share of u, d, m, h, i, r, g, `+alias, ticket.UserID, ticket.DeviceID, ticket.RuntimeID, ticket.GrantVersion, target, ticket.DeviceKeyVersion, ticket.ProofKeyThumbprint).
		Scan(&scopeJSON, &workspace, &state, &result.organization, &result.installation)
	if errors.Is(err, sql.ErrNoRows) {
		return result, ErrAccessDenied
	}
	if err != nil {
		return result, ErrDatabaseUnavailable
	}
	var scope GrantScope
	if json.Unmarshal(scopeJSON, &scope) != nil {
		return result, ErrDatabaseUnavailable
	}
	if !grantScopeSubset(ticket.Scope, scope) || !slices.Contains(ticket.Scope.Actions, action) || !slices.Contains(scope.Actions, action) {
		return result, ErrAccessDenied
	}
	if workspaceID != "" {
		if !slices.Contains(ticket.Scope.Workspaces, workspaceID) || !slices.Contains(scope.Workspaces, workspaceID) {
			return result, ErrAccessDenied
		}
	} else if (state != "available" && state != "running" && !(state == "archived" && (action == "session.archive" || action == "message.submit" && files))) || !scopeIncludesSession(ticket.Scope, sessionID, workspace) || !scopeIncludesSession(scope, sessionID, workspace) {
		return result, ErrAccessDenied
	}
	return result, nil
}
