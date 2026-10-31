package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

var ErrCommandArchiveInvalid = errors.New("store: invalid command archive request")
var ErrCommandArchiveConflict = errors.New("store: command archive operation conflicts")
var ErrCommandArchiveTooLarge = errors.New("store: command archive source exceeds the per-entry limit")

const maxCommandArchiveEntry = 64 << 10

type CommandArchiveRequest struct {
	BatchID, DatabaseEpoch   string
	Limit, ColdDays, HotDays int
}

func (request CommandArchiveRequest) Valid() bool {
	return grantUUIDPattern.MatchString(request.BatchID) && grantUUIDPattern.MatchString(request.DatabaseEpoch) && request.HotDays >= 1 && request.HotDays <= 3650 && request.Limit >= 1 && request.Limit <= 128 && request.ColdDays >= 0 && request.ColdDays <= 3650
}

type CommandArchiveResult struct {
	BatchID       string    `json:"batch_id"`
	DatabaseEpoch string    `json:"database_epoch"`
	Limit         int       `json:"limit"`
	ColdDays      int       `json:"cold_days"`
	HotDays       int       `json:"hot_days"`
	Cutoff        time.Time `json:"cutoff"`
	ArchivedAt    time.Time `json:"archived_at"`
	RetainUntil   time.Time `json:"retain_until"`
	Entries       int       `json:"entries"`
}

func readCommandArchive(ctx context.Context, tx *sql.Tx, id string) (CommandArchiveResult, error) {
	var result CommandArchiveResult
	err := tx.QueryRowContext(ctx, `select id::text,database_epoch::text,batch_limit,cold_days,hot_days,cutoff,archived_at,retain_until,entry_count
	 from command_archive_batches where id=$1`, id).Scan(&result.BatchID, &result.DatabaseEpoch, &result.Limit, &result.ColdDays, &result.HotDays, &result.Cutoff, &result.ArchivedAt, &result.RetainUntil, &result.Entries)
	result.Cutoff = result.Cutoff.UTC()
	result.ArchivedAt = result.ArchivedAt.UTC()
	result.RetainUntil = result.RetainUntil.UTC()
	return result, err
}

// ArchiveCommandHistory atomically moves bounded old terminal command rows into protected
// database history. It never uses timestamps or sequences as a completeness
// watermark; a late-committing row remains eligible in a later batch.
func (postgres *Postgres) ArchiveCommandHistory(ctx context.Context, request CommandArchiveRequest) (CommandArchiveResult, error) {
	if !request.Valid() {
		return CommandArchiveResult{}, ErrCommandArchiveInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return CommandArchiveResult{}, ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `select pg_advisory_xact_lock(hashtextextended('dsh-command-archive:'||$1::text,0))`, request.BatchID); err != nil {
		return CommandArchiveResult{}, ErrDatabaseUnavailable
	}
	if _, err := lockRecoveryReady(ctx, tx, request.DatabaseEpoch); err != nil {
		return CommandArchiveResult{}, err
	}
	previous, err := readCommandArchive(ctx, tx, request.BatchID)
	if err == nil {
		if previous.DatabaseEpoch != request.DatabaseEpoch || previous.Limit != request.Limit || previous.ColdDays != request.ColdDays || previous.HotDays != request.HotDays {
			return CommandArchiveResult{}, ErrCommandArchiveConflict
		}
		if tx.Commit() != nil {
			return CommandArchiveResult{}, ErrDatabaseUnavailable
		}
		return previous, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return CommandArchiveResult{}, ErrDatabaseUnavailable
	}
	result := CommandArchiveResult{BatchID: request.BatchID, DatabaseEpoch: request.DatabaseEpoch, Limit: request.Limit, ColdDays: request.ColdDays, HotDays: request.HotDays}
	if err := tx.QueryRowContext(ctx, `with moment as materialized(select clock_timestamp() as now)
	 select now,now-make_interval(hours=>$2*24),now+make_interval(hours=>$1*24) from moment`, request.ColdDays, request.HotDays).
		Scan(&result.ArchivedAt, &result.Cutoff, &result.RetainUntil); err != nil {
		return CommandArchiveResult{}, ErrDatabaseUnavailable
	}
	result.ArchivedAt, result.Cutoff, result.RetainUntil = result.ArchivedAt.UTC(), result.Cutoff.UTC(), result.RetainUntil.UTC()
	rows, err := tx.QueryContext(ctx, `select device_id::text,request_id::text,octet_length(to_jsonb(c)::text) from commands c
        where state in ('settled','rejected') and created_at<=$1 and updated_at<=$1
        order by updated_at,device_id,request_id limit $2 for update skip locked`, result.Cutoff, request.Limit)
	if err != nil {
		return CommandArchiveResult{}, ErrDatabaseUnavailable
	}
	devices, ids := make([]string, 0, request.Limit), make([]string, 0, request.Limit)
	for rows.Next() {
		var device, id string
		var size int
		if err := rows.Scan(&device, &id, &size); err != nil {
			_ = rows.Close()
			return CommandArchiveResult{}, ErrDatabaseUnavailable
		}
		if size > maxCommandArchiveEntry {
			_ = rows.Close()
			return CommandArchiveResult{}, ErrCommandArchiveTooLarge
		}
		devices = append(devices, device)
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return CommandArchiveResult{}, ErrDatabaseUnavailable
	}
	if err := rows.Close(); err != nil {
		return CommandArchiveResult{}, ErrDatabaseUnavailable
	}
	result.Entries = len(ids)
	if err := tx.QueryRowContext(ctx, `insert into command_archive_batches(id,database_epoch,batch_limit,cold_days,hot_days,cutoff,archived_at,retain_until,entry_count)
	 values($1,$2,$3,$4,$5,$6,$7,$8,$9) returning cutoff,archived_at,retain_until`, result.BatchID, result.DatabaseEpoch, result.Limit, result.ColdDays, result.HotDays, result.Cutoff, result.ArchivedAt, result.RetainUntil, result.Entries).
		Scan(&result.Cutoff, &result.ArchivedAt, &result.RetainUntil); err != nil {
		return CommandArchiveResult{}, ErrDatabaseUnavailable
	}
	result.ArchivedAt, result.Cutoff, result.RetainUntil = result.ArchivedAt.UTC(), result.Cutoff.UTC(), result.RetainUntil.UTC()
	metadata, _ := json.Marshal(result)
	if _, err := tx.ExecContext(ctx, `insert into audit_log(actor_type,actor_id,action,result,metadata)
	 values('system',current_user,'command.archive.batch','success',$1::jsonb||jsonb_build_object('db_session_user',session_user))`, string(metadata)); err != nil {
		return CommandArchiveResult{}, ErrDatabaseUnavailable
	}
	copied, err := tx.ExecContext(ctx, `insert into command_archive
        select c.*,$1,to_jsonb(c),pg_current_xact_id() from commands c
        join unnest($2::uuid[],$3::uuid[]) as selected(device_id,request_id) using(device_id,request_id)`, result.BatchID, devices, ids)
	if err != nil {
		return CommandArchiveResult{}, ErrDatabaseUnavailable
	}
	if count, err := copied.RowsAffected(); err != nil || count != int64(result.Entries) {
		return CommandArchiveResult{}, ErrDatabaseUnavailable
	}
	removed, err := tx.ExecContext(ctx, `delete from commands c using unnest($1::uuid[],$2::uuid[]) as selected(device_id,request_id)
        where c.device_id=selected.device_id and c.request_id=selected.request_id`, devices, ids)
	if err != nil {
		return CommandArchiveResult{}, ErrDatabaseUnavailable
	}
	if count, err := removed.RowsAffected(); err != nil || count != int64(result.Entries) {
		return CommandArchiveResult{}, ErrDatabaseUnavailable
	}
	if tx.Commit() != nil {
		return CommandArchiveResult{}, ErrDatabaseUnavailable
	}
	return result, nil
}
