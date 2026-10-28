package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

var ErrAuditArchiveInvalid = errors.New("store: invalid audit archive request")
var ErrAuditArchiveConflict = errors.New("store: audit archive operation conflicts")
var ErrAuditArchiveTooLarge = errors.New("store: audit archive source exceeds the per-entry limit")

const maxAuditArchiveEntry = 256 << 10

type AuditArchiveRequest struct {
	BatchID, DatabaseEpoch string
	Limit, RetentionYears  int
}

func (request AuditArchiveRequest) Valid() bool {
	return grantUUIDPattern.MatchString(request.BatchID) && grantUUIDPattern.MatchString(request.DatabaseEpoch) && request.Limit >= 1 && request.Limit <= 128 && request.RetentionYears >= 1 && request.RetentionYears <= 10
}

type AuditArchiveResult struct {
	BatchID        string    `json:"batch_id"`
	DatabaseEpoch  string    `json:"database_epoch"`
	Limit          int       `json:"limit"`
	RetentionYears int       `json:"retention_years"`
	Cutoff         time.Time `json:"cutoff"`
	ArchivedAt     time.Time `json:"archived_at"`
	RetainUntil    time.Time `json:"retain_until"`
	Entries        int       `json:"entries"`
}

func readAuditArchive(ctx context.Context, tx *sql.Tx, id string) (AuditArchiveResult, error) {
	var result AuditArchiveResult
	err := tx.QueryRowContext(ctx, `select id::text,database_epoch::text,batch_limit,retention_years,cutoff,archived_at,retain_until,entry_count
	 from audit_archive_batches where id=$1`, id).Scan(&result.BatchID, &result.DatabaseEpoch, &result.Limit, &result.RetentionYears, &result.Cutoff, &result.ArchivedAt, &result.RetainUntil, &result.Entries)
	result.Cutoff = result.Cutoff.UTC()
	result.ArchivedAt = result.ArchivedAt.UTC()
	result.RetainUntil = result.RetainUntil.UTC()
	return result, err
}

// ArchiveAuditHistory atomically moves bounded old audit rows into protected
// database history. It never uses timestamps or sequences as a completeness
// watermark; a late-committing row remains eligible in a later batch.
func (postgres *Postgres) ArchiveAuditHistory(ctx context.Context, request AuditArchiveRequest) (AuditArchiveResult, error) {
	if !request.Valid() {
		return AuditArchiveResult{}, ErrAuditArchiveInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return AuditArchiveResult{}, ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `select pg_advisory_xact_lock(hashtextextended('dsh-audit-archive:'||$1::text,0))`, request.BatchID); err != nil {
		return AuditArchiveResult{}, ErrDatabaseUnavailable
	}
	if _, err := lockRecoveryReady(ctx, tx, request.DatabaseEpoch); err != nil {
		return AuditArchiveResult{}, err
	}
	previous, err := readAuditArchive(ctx, tx, request.BatchID)
	if err == nil {
		if previous.DatabaseEpoch != request.DatabaseEpoch || previous.Limit != request.Limit || previous.RetentionYears != request.RetentionYears {
			return AuditArchiveResult{}, ErrAuditArchiveConflict
		}
		if tx.Commit() != nil {
			return AuditArchiveResult{}, ErrDatabaseUnavailable
		}
		return previous, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return AuditArchiveResult{}, ErrDatabaseUnavailable
	}
	result := AuditArchiveResult{BatchID: request.BatchID, DatabaseEpoch: request.DatabaseEpoch, Limit: request.Limit, RetentionYears: request.RetentionYears}
	if err := tx.QueryRowContext(ctx, `with moment as materialized(select clock_timestamp() as now)
	 select now,now-interval '2160 hours',((now at time zone 'UTC')+make_interval(years=>$1)) at time zone 'UTC' from moment`, request.RetentionYears).
		Scan(&result.ArchivedAt, &result.Cutoff, &result.RetainUntil); err != nil {
		return AuditArchiveResult{}, ErrDatabaseUnavailable
	}
	result.ArchivedAt, result.Cutoff, result.RetainUntil = result.ArchivedAt.UTC(), result.Cutoff.UTC(), result.RetainUntil.UTC()
	rows, err := tx.QueryContext(ctx, `select a.id,octet_length(to_jsonb(a)::text) from audit_log a
	 where a.ts<=$1 order by a.ts,a.id limit $2 for update skip locked`, result.Cutoff, request.Limit)
	if err != nil {
		return AuditArchiveResult{}, ErrDatabaseUnavailable
	}
	ids := make([]int64, 0, request.Limit)
	for rows.Next() {
		var id int64
		var size int
		if err := rows.Scan(&id, &size); err != nil {
			_ = rows.Close()
			return AuditArchiveResult{}, ErrDatabaseUnavailable
		}
		if size > maxAuditArchiveEntry {
			_ = rows.Close()
			return AuditArchiveResult{}, ErrAuditArchiveTooLarge
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return AuditArchiveResult{}, ErrDatabaseUnavailable
	}
	if err := rows.Close(); err != nil {
		return AuditArchiveResult{}, ErrDatabaseUnavailable
	}
	result.Entries = len(ids)
	if err := tx.QueryRowContext(ctx, `insert into audit_archive_batches(id,database_epoch,batch_limit,retention_years,cutoff,archived_at,retain_until,entry_count)
	 values($1,$2,$3,$4,$5,$6,$7,$8) returning cutoff,archived_at,retain_until`, result.BatchID, result.DatabaseEpoch, result.Limit, result.RetentionYears, result.Cutoff, result.ArchivedAt, result.RetainUntil, result.Entries).
		Scan(&result.Cutoff, &result.ArchivedAt, &result.RetainUntil); err != nil {
		return AuditArchiveResult{}, ErrDatabaseUnavailable
	}
	result.ArchivedAt, result.Cutoff, result.RetainUntil = result.ArchivedAt.UTC(), result.Cutoff.UTC(), result.RetainUntil.UTC()
	metadata, _ := json.Marshal(result)
	if _, err := tx.ExecContext(ctx, `insert into audit_log(actor_type,actor_id,action,result,metadata)
	 values('system',current_user,'audit.archive.batch','success',$1::jsonb||jsonb_build_object('db_session_user',session_user))`, string(metadata)); err != nil {
		return AuditArchiveResult{}, ErrDatabaseUnavailable
	}
	copied, err := tx.ExecContext(ctx, `insert into audit_log_archive(source_id,batch_id,batch_epoch,source_epoch,source_ts,source)
	 select a.id,$1,$2,a.database_epoch,a.ts,to_jsonb(a) from audit_log a where a.id=any($3::bigint[])`, result.BatchID, result.DatabaseEpoch, ids)
	if err != nil {
		return AuditArchiveResult{}, ErrDatabaseUnavailable
	}
	if count, err := copied.RowsAffected(); err != nil || count != int64(result.Entries) {
		return AuditArchiveResult{}, ErrDatabaseUnavailable
	}
	removed, err := tx.ExecContext(ctx, `delete from audit_log where id=any($1::bigint[])`, ids)
	if err != nil {
		return AuditArchiveResult{}, ErrDatabaseUnavailable
	}
	if count, err := removed.RowsAffected(); err != nil || count != int64(result.Entries) {
		return AuditArchiveResult{}, ErrDatabaseUnavailable
	}
	if tx.Commit() != nil {
		return AuditArchiveResult{}, ErrDatabaseUnavailable
	}
	return result, nil
}
