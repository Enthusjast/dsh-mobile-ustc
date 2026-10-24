package store

import (
	"context"
	"encoding/json"
)

type RealtimeConnectionLease struct {
	Role               string     `json:"role"`
	ConnectionID       string     `json:"connection_id"`
	RuntimeID          string     `json:"runtime_id"`
	RuntimeEpoch       *string    `json:"runtime_epoch"`
	InstallationID     *string    `json:"installation_id"`
	KeyVersion         int64      `json:"key_version"`
	UserID             *string    `json:"user_id"`
	DeviceID           *string    `json:"device_id"`
	DeviceKeyVersion   int64      `json:"device_key_version"`
	ProofKeyThumbprint string     `json:"proof_key_thumbprint"`
	GrantVersion       int64      `json:"grant_version"`
	Scope              GrantScope `json:"scope"`
}

// InvalidRealtimeConnectionLeases checks at most 128 connections in one query.
// Foreground operations still perform their own resource/action authorization.
func (postgres *Postgres) InvalidRealtimeConnectionLeases(ctx context.Context, leases []RealtimeConnectionLease) ([]string, error) {
	if len(leases) > 128 {
		return nil, ErrGrantInvalid
	}
	for _, lease := range leases {
		if !grantUUIDPattern.MatchString(lease.ConnectionID) || !grantUUIDPattern.MatchString(lease.RuntimeID) ||
			(lease.Role != "device" && lease.Role != "installation") {
			return nil, ErrGrantInvalid
		}
	}
	encoded, err := json.Marshal(leases)
	if err != nil {
		return nil, ErrGrantInvalid
	}
	if len(leases) == 0 {
		return []string{}, nil
	}
	rows, err := postgres.DB.QueryContext(ctx, `
		select lease.connection_id from jsonb_to_recordset($1::jsonb) as lease(
			role text, connection_id text, runtime_id uuid, runtime_epoch uuid, installation_id uuid,
			key_version bigint, user_id uuid, device_id uuid, device_key_version bigint,
			proof_key_thumbprint text, grant_version bigint, scope jsonb
		)
		where (lease.role = 'device' and not exists (
			select 1 from users u
			join devices d on d.user_id = u.id and d.id = lease.device_id and d.revoked_at is null
			join org_memberships m on m.user_id = u.id
			join hosts h on h.org_id = m.org_id and h.state = 'active'
			join installations i on i.host_id = h.id and i.revoked_at is null
			join runtimes r on r.installation_id = i.id and r.id = lease.runtime_id and r.revoked_at is null and `+runtimeEnrollmentApprovedSQL+`
			join runtime_grants g on g.runtime_id = r.id and g.user_id = u.id and g.grant_version = lease.grant_version
			where u.id = lease.user_id and u.status = 'active' and d.key_version = lease.device_key_version
			  and d.proof_key_thumbprint = lease.proof_key_thumbprint
			  and g.revoked_at is null and (g.expires_at is null or g.expires_at > clock_timestamp())
			  and g.scope @> lease.scope
			  and not exists (
				select 1 from jsonb_array_elements_text(lease.scope->'workspaces') requested(id)
				where not exists (select 1 from workspaces w where w.runtime_id = r.id and w.id::text = requested.id)
			  )
			  and not exists (
				select 1 from jsonb_array_elements_text(lease.scope->'sessions') requested(id)
				where not exists (select 1 from sessions s where s.runtime_id = r.id and s.id::text = requested.id)
			  )
		)) or (lease.role = 'installation' and not exists (
			select 1 from runtimes r
			join installations i on i.id = r.installation_id and i.id = lease.installation_id and i.revoked_at is null
			join hosts h on h.id = i.host_id and h.state = 'active'
			where r.id = lease.runtime_id and r.epoch = lease.runtime_epoch and r.connection_id::text = lease.connection_id
			  and r.revoked_at is null and `+runtimeEnrollmentApprovedSQL+` and i.key_version = lease.key_version and r.connection_key_version = i.key_version
		))`, string(encoded))
	if err != nil {
		return nil, ErrDatabaseUnavailable
	}
	defer rows.Close()
	invalid := []string{}
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil {
			return nil, ErrDatabaseUnavailable
		}
		invalid = append(invalid, id)
	}
	if rows.Err() != nil {
		return nil, ErrDatabaseUnavailable
	}
	return invalid, nil
}
