package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
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
	ApprovalID   string
	CreatedAt    time.Time
}

func (postgres *Postgres) PendingControlEvents(ctx context.Context, limit int) ([]ControlEvent, error) {
	if limit < 1 || limit > 128 {
		return nil, ErrGrantInvalid
	}
	rows, err := postgres.DB.QueryContext(ctx, `
		select id::text, topic, payload, created_at from control_outbox
		where published_at is null and database_epoch=(select epoch from remote_recovery_state where slot=1 and phase='ready') and topic in ('device.revoked', 'runtime_grant.updated', 'runtime_grant.revoked',
		    'approval.pending', 'approval.decided', 'approval.ended', 'approval.result', 'approval.authorization.prepared', 'approval.device.revoked')
		order by created_at, id limit $1`, limit)
	if err != nil {
		return nil, ErrDatabaseUnavailable
	}
	return readControlEvents(rows)
}

func readControlEvents(rows *sql.Rows) ([]ControlEvent, error) {
	defer rows.Close()
	events := []ControlEvent{}
	for rows.Next() {
		var event ControlEvent
		var raw []byte
		if rows.Scan(&event.ID, &event.Topic, &raw, &event.CreatedAt) != nil {
			return nil, ErrDatabaseUnavailable
		}
		var payload struct {
			DeviceID     string `json:"device_id"`
			RuntimeID    string `json:"runtime_id"`
			UserID       string `json:"user_id"`
			GrantVersion int64  `json:"grant_version"`
			ApprovalID   string `json:"approval_id"`
		}
		if json.Unmarshal(raw, &payload) != nil {
			return nil, ErrGrantInvalid
		}
		event.DeviceID, event.RuntimeID, event.UserID, event.GrantVersion = payload.DeviceID, payload.RuntimeID, payload.UserID, payload.GrantVersion
		event.ApprovalID = payload.ApprovalID
		if event.Topic == "approval.device.revoked" {
			if !grantUUIDPattern.MatchString(event.RuntimeID) || !grantUUIDPattern.MatchString(event.DeviceID) {
				return nil, ErrGrantInvalid
			}
		} else if event.Topic == "approval.pending" || event.Topic == "approval.decided" || event.Topic == "approval.ended" || event.Topic == "approval.result" || event.Topic == "approval.authorization.prepared" {
			if !grantUUIDPattern.MatchString(event.RuntimeID) || !grantUUIDPattern.MatchString(event.ApprovalID) {
				return nil, ErrGrantInvalid
			}
		} else if event.Topic == "device.revoked" {
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
	_, err := postgres.DB.ExecContext(ctx, `update control_outbox set published_at = clock_timestamp() where id = $1 and published_at is null and database_epoch=(select epoch from remote_recovery_state where slot=1 and phase='ready')`, id)
	if err != nil {
		return ErrDatabaseUnavailable
	}
	return nil
}
