package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"dsh-mobile-ustc/services/remote/internal/files"
)

// Called only after the file status operation has authorized the original device.
func (repository *FileStore) FileMessageReference(ctx context.Context, id string) (*files.Delivery, error) {
	if !grantUUIDPattern.MatchString(id) {
		return nil, files.ErrInvalid
	}
	delivery := &files.Delivery{State: "bound"}
	err := repository.database.DB.QueryRowContext(ctx, `select r.request_id::text,c.state from file_message_refs r join command_records c on c.device_id=r.device_id and c.request_id=r.request_id where r.file_id=$1`, id).Scan(&delivery.RequestID, &delivery.CommandState)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, files.ErrUnavailable
	}
	return delivery, nil
}

// File references are reserved in the command transaction, before any Relay
// forwarding. A terminal original only reconciles its existing references.
func (postgres *Postgres) RecordRealtimeFileCommand(ctx context.Context, ticket TicketRedemption, host files.HostBinding, requestID, sessionID, digest, policy string, fileIDs []string, ready func() bool) (status CommandStatus, err error) {
	started := time.Now()
	defer func() { postgres.observeCommandStore(ctx, "file_admit", started, err) }()
	if len(fileIDs) < 1 || len(fileIDs) > 16 || !validSHA256Hex(policy) || ticket.RuntimeID != host.RuntimeID {
		return CommandStatus{}, files.ErrInvalid
	}
	ids := slices.Clone(fileIDs)
	slices.Sort(ids)
	for i, id := range ids {
		if !grantUUIDPattern.MatchString(id) || i > 0 && ids[i-1] == id {
			return CommandStatus{}, files.ErrInvalid
		}
	}
	reconcile := false
	status, err = postgres.recordRealtimeCommand(ctx, ticket, "message.submit", requestID, sessionID, digest, func(ctx context.Context, tx *sql.Tx, status CommandStatus) error {
		known, err := existingMessageFiles(ctx, tx, ticket, status, ids)
		if err != nil {
			return err
		}
		if status.State != "received" {
			if !known {
				return files.ErrAccess
			}
			return nil
		}
		// Only an already committed original can request read-only recovery.
		// It gets no replacement download, receipt or fresh message authority.
		fallback := func() error {
			if !known {
				return files.ErrStale
			}
			if _, _, err := hostFileBinding(ctx, tx, host); err != nil {
				return err
			}
			reconcile = true
			return nil
		}
		if ready == nil || !ready() {
			return fallback()
		}
		if _, err := tx.ExecContext(ctx, `savepoint file_message_admission`); err != nil {
			return files.ErrUnavailable
		}
		admissionErr := bindMessageFiles(ctx, tx, ticket, host, status, policy, ids)
		if admissionErr == nil && !ready() {
			admissionErr = files.ErrStale
		}
		if admissionErr != nil {
			if !known || (!errors.Is(admissionErr, files.ErrStale) && !errors.Is(admissionErr, files.ErrAccess)) {
				return admissionErr
			}
			if _, err := tx.ExecContext(ctx, `rollback to savepoint file_message_admission`); err != nil {
				return files.ErrUnavailable
			}
			if err := fallback(); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `release savepoint file_message_admission`); err != nil {
			return files.ErrUnavailable
		}
		return nil
	})
	status.ReconcileFiles = reconcile && status.State == "received"
	return status, err
}

func existingMessageFiles(ctx context.Context, tx *sql.Tx, ticket TicketRedemption, status CommandStatus, ids []string) (bool, error) {
	rows, err := tx.QueryContext(ctx, `select file_id::text from file_message_refs where device_id=$1 and request_id=$2 order by file_id`, ticket.DeviceID, status.RequestID)
	if err != nil {
		return false, files.ErrUnavailable
	}
	previous := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return false, files.ErrUnavailable
		}
		previous = append(previous, id)
	}
	rowErr := rows.Err()
	_ = rows.Close()
	if rowErr != nil {
		return false, files.ErrUnavailable
	}
	if len(previous) > 0 && !slices.Equal(previous, ids) {
		return false, files.ErrConflict
	}
	return slices.Equal(previous, ids), nil
}

func bindMessageFiles(ctx context.Context, tx *sql.Tx, ticket TicketRedemption, host files.HostBinding, status CommandStatus, policy string, ids []string) error {
	for _, id := range ids {
		record, err := loadFile(ctx, tx, id, "for update of f,t")
		if errors.Is(err, sql.ErrNoRows) {
			return files.ErrAccess
		}
		if err != nil {
			return files.ErrUnavailable
		}
		if record.Direction != "to_host" || record.RuntimeID != host.RuntimeID || record.SessionID != status.SessionID || record.UploaderID != ticket.UserID || record.DeviceID != ticket.DeviceID || record.KeyVersion != ticket.DeviceKeyVersion || record.ProofKeyJKT != ticket.ProofKeyThumbprint || record.GrantVersion != ticket.GrantVersion {
			return files.ErrAccess
		}
		var staged string
		err = tx.QueryRowContext(ctx, `select id::text from file_handoffs where file_id=$1 and connection_id=$2 and runtime_epoch=$3 and state='staged'`, id, host.ConnectionID, host.RuntimeEpoch).Scan(&staged)
		if errors.Is(err, sql.ErrNoRows) {
			return files.ErrStale
		}
		if err != nil {
			return files.ErrUnavailable
		}
		handoff, err := loadHandoff(ctx, tx, staged)
		if err != nil {
			return err
		}
		if _, err := validHandoff(ctx, tx, handoff, host, policy); err != nil {
			return err
		}
		var boundDevice, boundRequest string
		err = tx.QueryRowContext(ctx, `select device_id::text,request_id::text from file_message_refs where file_id=$1`, id).Scan(&boundDevice, &boundRequest)
		if err == nil {
			if boundDevice != ticket.DeviceID || boundRequest != status.RequestID {
				return files.ErrConflict
			}
			if _, err := tx.ExecContext(ctx, `update file_message_refs set handoff_id=$2 where file_id=$1`, id, staged); err != nil {
				return files.ErrUnavailable
			}
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return files.ErrUnavailable
		}
		if _, err := tx.ExecContext(ctx, `insert into file_message_refs(file_id,device_id,request_id,handoff_id) values($1,$2,$3,$4)`, id, ticket.DeviceID, status.RequestID, staged); err != nil {
			return files.ErrUnavailable
		}
		metadata, _ := json.Marshal(map[string]any{"file_id": id, "handoff_id": staged, "request_id": status.RequestID, "payload_sha256": status.PayloadSHA256})
		if _, err := tx.ExecContext(ctx, `insert into audit_log(org_id,actor_type,actor_id,device_id,runtime_id,session_id,action,result,metadata) values($1,'device',$2::uuid::text,$2,$3,$4,'file.message_bound','success',$5::jsonb)`, record.OrganizationID, ticket.DeviceID, record.RuntimeID, record.SessionID, string(metadata)); err != nil {
			return files.ErrUnavailable
		}
	}
	return nil
}

// Existing handoffs may remain live while their message is queued locally, but
// completed or uncertain messages never acquire fresh file authority.
func fileMessageAllowsHandoff(ctx context.Context, tx *sql.Tx, id string, fresh bool) error {
	var state string
	err := tx.QueryRowContext(ctx, `select c.state from file_message_refs r join command_records c on c.device_id=r.device_id and c.request_id=r.request_id where r.file_id=$1`, id).Scan(&state)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return files.ErrUnavailable
	}
	if state == "received" || !fresh && (state == "host_accepted" || state == "dispatching") {
		return nil
	}
	return files.ErrStale
}
