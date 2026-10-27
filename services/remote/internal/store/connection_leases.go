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
// Anchor each batch to its exact runtime before joining organization membership;
// a shared organization must not fan out across every host for each lease.
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
		with leases as materialized (select * from jsonb_to_recordset($1::jsonb) as item(
			role text, connection_id text, runtime_id uuid, runtime_epoch uuid, installation_id uuid,
			key_version bigint, user_id uuid, device_id uuid, device_key_version bigint,
			proof_key_thumbprint text, grant_version bigint, scope jsonb
		))
		select lease.connection_id from leases lease
		left join runtimes r on r.id=lease.runtime_id and r.revoked_at is null and `+runtimeEnrollmentApprovedSQL+`
		left join installations i on i.id=r.installation_id and i.revoked_at is null
		left join hosts h on h.id=i.host_id and h.state='active'
		left join users u on u.id=lease.user_id and u.status='active'
		left join devices d on d.id=lease.device_id and d.user_id=u.id and d.revoked_at is null
		    and d.key_version=lease.device_key_version and d.proof_key_thumbprint=lease.proof_key_thumbprint
		left join org_memberships m on m.user_id=u.id and m.org_id=h.org_id
		left join runtime_grants g on g.runtime_id=r.id and g.user_id=u.id and g.grant_version=lease.grant_version
		    and g.revoked_at is null and (g.expires_at is null or g.expires_at>clock_timestamp()) and g.scope@>lease.scope
		    and jsonb_typeof(lease.scope->'actions')='array' and jsonb_typeof(lease.scope->'workspaces')='array' and jsonb_typeof(lease.scope->'sessions')='array'
		where lease.role='device' and (
		    r.id is null or i.id is null or h.id is null or u.id is null or d.id is null or m.user_id is null or g.runtime_id is null
		    or exists (
		        select 1 from jsonb_array_elements_text(case when jsonb_typeof(lease.scope->'workspaces')='array' then lease.scope->'workspaces' else '[]'::jsonb end) requested(id)
		        where not exists (select 1 from workspaces w where w.runtime_id=r.id and w.id::text=requested.id)
		    )
		    or exists (
		        select 1 from jsonb_array_elements_text(case when jsonb_typeof(lease.scope->'sessions')='array' then lease.scope->'sessions' else '[]'::jsonb end) requested(id)
		        where not exists (select 1 from sessions s where s.runtime_id=r.id and s.id::text=requested.id)
		    )
		)
		union all
		select lease.connection_id from leases lease
		left join runtimes r on r.id=lease.runtime_id and r.epoch=lease.runtime_epoch and r.connection_id::text=lease.connection_id
		    and r.revoked_at is null and `+runtimeEnrollmentApprovedSQL+`
		left join installations i on i.id=r.installation_id and i.id=lease.installation_id and i.revoked_at is null
		    and i.key_version=lease.key_version and r.connection_key_version=i.key_version
		left join hosts h on h.id=i.host_id and h.state='active'
		where lease.role='installation' and (r.id is null or i.id is null or h.id is null)`, string(encoded))
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
