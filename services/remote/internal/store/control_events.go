package store

import (
	"context"
	"encoding/json"
)

// ControlEvent is the metadata required to invalidate local connection leases.
// Session content and grant scope bodies are not passed to the relay worker.
type ControlEvent struct {
	ID           string
	Topic        string
	DeviceID     string
	RuntimeID    string
	UserID       string
	GrantVersion int64
}

func (postgres *Postgres) PendingControlEvents(ctx context.Context, limit int) ([]ControlEvent, error) {
	if limit < 1 || limit > 128 {
		return nil, ErrGrantInvalid
	}
	rows, err := postgres.DB.QueryContext(ctx, `
		select id::text, topic, payload from control_outbox
		where published_at is null and topic in ('device.revoked', 'runtime_grant.updated', 'runtime_grant.revoked')
		order by created_at, id limit $1`, limit)
	if err != nil {
		return nil, ErrDatabaseUnavailable
	}
	defer rows.Close()
	events := []ControlEvent{}
	for rows.Next() {
		var event ControlEvent
		var raw []byte
		if rows.Scan(&event.ID, &event.Topic, &raw) != nil {
			return nil, ErrDatabaseUnavailable
		}
		var payload struct {
			DeviceID     string `json:"device_id"`
			RuntimeID    string `json:"runtime_id"`
			UserID       string `json:"user_id"`
			GrantVersion int64  `json:"grant_version"`
		}
		if json.Unmarshal(raw, &payload) != nil {
			return nil, ErrGrantInvalid
		}
		event.DeviceID, event.RuntimeID, event.UserID, event.GrantVersion = payload.DeviceID, payload.RuntimeID, payload.UserID, payload.GrantVersion
		if event.Topic == "device.revoked" {
			if !grantUUIDPattern.MatchString(event.DeviceID) {
				return nil, ErrGrantInvalid
			}
		} else if !grantUUIDPattern.MatchString(event.RuntimeID) || !grantUUIDPattern.MatchString(event.UserID) || event.GrantVersion < 1 {
			return nil, ErrGrantInvalid
		}
		events = append(events, event)
	}
	if rows.Err() != nil {
		return nil, ErrDatabaseUnavailable
	}
	return events, nil
}

// Publication is acknowledged after all local invalidations finish. A crash
// between apply and acknowledgement replays the idempotent invalidation.
func (postgres *Postgres) MarkControlEventPublished(ctx context.Context, id string) error {
	if !grantUUIDPattern.MatchString(id) {
		return ErrGrantInvalid
	}
	_, err := postgres.DB.ExecContext(ctx, `update control_outbox set published_at = clock_timestamp() where id = $1 and published_at is null`, id)
	if err != nil {
		return ErrDatabaseUnavailable
	}
	return nil
}
