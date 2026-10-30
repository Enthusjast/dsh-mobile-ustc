package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

var ErrControlArchiveInvalid = errors.New("store: invalid control archive request")
var ErrControlArchiveConflict = errors.New("store: control archive operation conflicts")

// One namespace shared by archive maintenance, consumer registration and acks.
// Acquire before recovery/consumer locks; normal renewal/reads do not need it.
func lockControlArchive(ctx context.Context, tx *sql.Tx, exclusive bool) error {
	query := `select pg_advisory_xact_lock_shared(1380012611,1)`
	if exclusive {
		query = `select pg_advisory_xact_lock(1380012611,1)`
	}
	if _, err := tx.ExecContext(ctx, query); err != nil {
		return ErrDatabaseUnavailable
	}
	return nil
}

type ControlArchiveRequest struct {
	BatchID, DatabaseEpoch string
	Limit                  int
	RetentionYears         int
}

func (request ControlArchiveRequest) Valid() bool {
	return grantUUIDPattern.MatchString(request.BatchID) && grantUUIDPattern.MatchString(request.DatabaseEpoch) && request.Limit >= 1 && request.Limit <= 128 && request.RetentionYears >= 1 && request.RetentionYears <= 10
}

type ControlArchiveResult struct {
	BatchID             string    `json:"batch_id"`
	DatabaseEpoch       string    `json:"database_epoch"`
	Limit               int       `json:"limit"`
	RetentionYears      int       `json:"retention_years"`
	Cutoff              time.Time `json:"cutoff"`
	ArchivedAt          time.Time `json:"archived_at"`
	RetainUntil         time.Time `json:"retain_until"`
	Events              int       `json:"events"`
	PreviousEpochEvents int       `json:"previous_epoch_events"`
}

func readControlArchive(ctx context.Context, tx *sql.Tx, id string) (ControlArchiveResult, error) {
	var result ControlArchiveResult
	err := tx.QueryRowContext(ctx, `select id::text,database_epoch::text,batch_limit,retention_years,cutoff,archived_at,retain_until,event_count,previous_epoch_count
	 from control_archive_batches where id=$1`, id).Scan(&result.BatchID, &result.DatabaseEpoch, &result.Limit, &result.RetentionYears, &result.Cutoff, &result.ArchivedAt, &result.RetainUntil, &result.Events, &result.PreviousEpochEvents)
	return result, err
}

// ArchiveControlEvents atomically moves only safely retired source metadata.
// The history table is NOT an external encrypted backup or a replay source.
func (postgres *Postgres) ArchiveControlEvents(ctx context.Context, input ControlArchiveRequest) (ControlArchiveResult, error) {
	if !input.Valid() {
		return ControlArchiveResult{}, ErrControlArchiveInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	tx, err := postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return ControlArchiveResult{}, ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	if err := lockControlArchive(ctx, tx, true); err != nil {
		return ControlArchiveResult{}, err
	}
	if _, err := lockRecoveryReady(ctx, tx, input.DatabaseEpoch); err != nil {
		return ControlArchiveResult{}, err
	}
	existing, err := readControlArchive(ctx, tx, input.BatchID)
	if err == nil {
		if existing.DatabaseEpoch != input.DatabaseEpoch || existing.Limit != input.Limit || existing.RetentionYears != input.RetentionYears {
			return ControlArchiveResult{}, ErrControlArchiveConflict
		}
		if tx.Commit() != nil {
			return ControlArchiveResult{}, ErrDatabaseUnavailable
		}
		return existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return ControlArchiveResult{}, ErrDatabaseUnavailable
	}
	result := ControlArchiveResult{BatchID: input.BatchID, DatabaseEpoch: input.DatabaseEpoch, Limit: input.Limit, RetentionYears: input.RetentionYears}
	if err := tx.QueryRowContext(ctx, `with moment as materialized(select clock_timestamp() as now)
	 select now,now-interval '2160 hours',((now at time zone 'UTC')+make_interval(years => $1)) at time zone 'UTC' from moment`, input.RetentionYears).Scan(&result.ArchivedAt, &result.Cutoff, &result.RetainUntil); err != nil {
		return ControlArchiveResult{}, ErrDatabaseUnavailable
	}
	// CASE prevents evaluating source-cluster XID visibility in the current
	// namespace. A released recovery is the sole basis for retiring old epochs.
	err = tx.QueryRowContext(ctx, `with candidates as materialized (
	 select e.* from control_outbox e
	 where e.created_at<=$3 and e.topic in ('device.revoked','runtime.revoked','runtime_grant.updated','runtime_grant.revoked','approval.pending','approval.decided',
	   'approval.ended','approval.result','approval.authorization.prepared','approval.device.revoked')
	 and case when e.database_epoch=$2::uuid then
	   e.published_at is not null and e.published_at<=$3 and not exists(
	     select 1 from control_consumers c where c.database_epoch=$2::uuid
	     and not(pg_visible_in_snapshot(e.producer_xid,c.coverage) or exists(
	       select 1 from control_event_acks a where a.node_id=c.node_id and a.event_id=e.id)))
	 else exists(select 1 from remote_recovery_runs r where r.source_epoch=e.database_epoch and r.phase='ready') end
	 order by e.created_at,e.id limit $4 for update of e skip locked
	), copied as (
	 insert into control_outbox_archive(event_id,batch_id,batch_epoch,database_epoch,topic,source_created_at,source,reason,archived_at,retain_until)
	 select c.id,$1,$2,c.database_epoch,c.topic,c.created_at,to_jsonb(c),
	   case when c.database_epoch=$2::uuid then 'covered' else 'recovered_epoch' end,$5,$6 from candidates c
	 returning event_id,database_epoch
	) select count(*),count(*) filter(where database_epoch<>$2::uuid) from copied`,
		input.BatchID, input.DatabaseEpoch, result.Cutoff, input.Limit, result.ArchivedAt, result.RetainUntil).Scan(&result.Events, &result.PreviousEpochEvents)
	if err != nil {
		return ControlArchiveResult{}, ErrDatabaseUnavailable
	}
	// Copy remaining per-node facts before the source DELETE cascades its live
	// acknowledgements. Never reinterpret source-epoch XIDs here.
	if _, err := tx.ExecContext(ctx, `insert into control_event_ack_archive(node_id,event_id,applied_at,source)
	 select a.node_id,a.event_id,a.applied_at,to_jsonb(a) from control_event_acks a
	 join control_outbox_archive e on e.event_id=a.event_id where e.batch_id=$1`, input.BatchID); err != nil {
		return ControlArchiveResult{}, ErrDatabaseUnavailable
	}
	removed, err := tx.ExecContext(ctx, `delete from control_outbox e using control_outbox_archive a
	 where a.batch_id=$1 and a.event_id=e.id`, input.BatchID)
	if err != nil {
		return ControlArchiveResult{}, ErrDatabaseUnavailable
	}
	if count, err := removed.RowsAffected(); err != nil || count != int64(result.Events) {
		return ControlArchiveResult{}, ErrDatabaseUnavailable
	}
	if _, err := tx.ExecContext(ctx, `insert into control_archive_batches(id,database_epoch,batch_limit,retention_years,cutoff,archived_at,retain_until,event_count,previous_epoch_count)
	 values($1,$2,$3,$4,$5,$6,$7,$8,$9)`, result.BatchID, result.DatabaseEpoch, result.Limit, result.RetentionYears, result.Cutoff, result.ArchivedAt, result.RetainUntil, result.Events, result.PreviousEpochEvents); err != nil {
		return ControlArchiveResult{}, ErrDatabaseUnavailable
	}
	metadata, _ := json.Marshal(result)
	if _, err := tx.ExecContext(ctx, `insert into audit_log(actor_type,actor_id,action,result,metadata)
	 values('system',current_user,'control.archive','success',$1::jsonb||jsonb_build_object('db_session_user',session_user))`, string(metadata)); err != nil {
		return ControlArchiveResult{}, ErrDatabaseUnavailable
	}
	if tx.Commit() != nil {
		return ControlArchiveResult{}, ErrDatabaseUnavailable
	}
	return result, nil
}
