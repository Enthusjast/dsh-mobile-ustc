package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

var ErrControlConsumerFenced = errors.New("store: control consumer is fenced")
var ErrControlConsumerInUse = errors.New("store: control consumer already active")

type ControlConsumer struct {
	postgres         *Postgres
	node, generation string
	durable          bool
}

func (consumer *ControlConsumer) NodeID() string { return consumer.node }

// A configured ID retains its covered snapshot across a clean restart or an
// expired incarnation. The default ephemeral ID starts from current authority.
func (postgres *Postgres) NewControlConsumer(ctx context.Context, node string) (*ControlConsumer, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	durable := node != ""
	if durable && !grantUUIDPattern.MatchString(node) {
		return nil, ErrDatabaseConfig
	}
	transaction, err := postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, ErrDatabaseUnavailable
	}
	defer transaction.Rollback()
	var generated, generation string
	if err := transaction.QueryRowContext(ctx, `select gen_random_uuid()::text,gen_random_uuid()::text`).Scan(&generated, &generation); err != nil {
		return nil, ErrDatabaseUnavailable
	}
	if !durable {
		node = generated
	}
	if _, err := transaction.ExecContext(ctx, `insert into control_consumers(node_id,generation,coverage,durable,lease_until)
        values($1,$2,pg_current_snapshot(),$3,clock_timestamp()+interval '10 seconds') on conflict do nothing`, node, generation, durable); err != nil {
		return nil, ErrDatabaseUnavailable
	}
	var previous string
	var until, now time.Time
	var previousDurable bool
	if err := transaction.QueryRowContext(ctx, `select generation::text,lease_until,durable from control_consumers where node_id=$1 for update`, node).Scan(&previous, &until, &previousDurable); err != nil {
		return nil, ErrDatabaseUnavailable
	}
	if err := transaction.QueryRowContext(ctx, `select clock_timestamp()`).Scan(&now); err != nil {
		return nil, ErrDatabaseUnavailable
	}
	if previousDurable != durable {
		return nil, ErrDatabaseConfig
	}
	if previous != generation {
		if until.After(now) {
			return nil, ErrControlConsumerInUse
		}
		if _, err := transaction.ExecContext(ctx, `update control_consumers set generation=$2,lease_until=clock_timestamp()+interval '10 seconds',renewed_at=clock_timestamp() where node_id=$1`, node, generation); err != nil {
			return nil, ErrDatabaseUnavailable
		}
	}
	if err := transaction.Commit(); err != nil {
		return nil, ErrDatabaseUnavailable
	}
	return &ControlConsumer{postgres, node, generation, durable}, nil
}

func (consumer *ControlConsumer) lock(ctx context.Context, transaction *sql.Tx) (string, error) {
	var generation, coverage string
	var until, now time.Time
	err := transaction.QueryRowContext(ctx, `select generation::text,coverage::text,lease_until from control_consumers where node_id=$1 for update`, consumer.node).Scan(&generation, &coverage, &until)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrControlConsumerFenced
	}
	if err != nil {
		return "", ErrDatabaseUnavailable
	}
	if err := transaction.QueryRowContext(ctx, `select clock_timestamp()`).Scan(&now); err != nil {
		return "", ErrDatabaseUnavailable
	}
	if generation != consumer.generation || !until.After(now) {
		return "", ErrControlConsumerFenced
	}
	return coverage, nil
}

func (consumer *ControlConsumer) Renew(ctx context.Context) error {
	transaction, err := consumer.postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return ErrDatabaseUnavailable
	}
	defer transaction.Rollback()
	if _, err := consumer.lock(ctx, transaction); err != nil {
		return err
	}
	if _, err := transaction.ExecContext(ctx, `update control_consumers set lease_until=clock_timestamp()+interval '10 seconds',renewed_at=clock_timestamp() where node_id=$1 and generation=$2`, consumer.node, consumer.generation); err != nil {
		return ErrDatabaseUnavailable
	}
	if err := transaction.Commit(); err != nil {
		return ErrDatabaseUnavailable
	}
	return nil
}

func (consumer *ControlConsumer) Release(ctx context.Context) error {
	query := `update control_consumers set lease_until=clock_timestamp() where node_id=$1 and generation=$2`
	if !consumer.durable {
		query = `delete from control_consumers where node_id=$1 and generation=$2`
	}
	if _, err := consumer.postgres.DB.ExecContext(ctx, query, consumer.node, consumer.generation); err != nil {
		return ErrDatabaseUnavailable
	}
	return nil
}

func (consumer *ControlConsumer) PendingControlEvents(ctx context.Context, limit int) ([]ControlEvent, error) {
	if limit < 1 || limit > 128 {
		return nil, ErrGrantInvalid
	}
	transaction, err := consumer.postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, ErrDatabaseUnavailable
	}
	defer transaction.Rollback()
	coverage, err := consumer.lock(ctx, transaction)
	if err != nil {
		return nil, err
	}
	// Capture BEFORE the candidate read. Any transaction committing after this
	// snapshot stays eligible even if the following statement sees no rows.
	var next string
	if err := transaction.QueryRowContext(ctx, `select pg_current_snapshot()::text`).Scan(&next); err != nil {
		return nil, ErrDatabaseUnavailable
	}
	rows, err := transaction.QueryContext(ctx, `select event.id::text,event.topic,event.payload,event.created_at from control_outbox event
        where event.producer_xid>=pg_snapshot_xmin($2::pg_snapshot) and not pg_visible_in_snapshot(event.producer_xid,$2::pg_snapshot)
          and event.topic in ('device.revoked','runtime_grant.updated','runtime_grant.revoked','approval.pending','approval.decided','approval.ended','approval.result','approval.authorization.prepared','approval.device.revoked')
          and not exists(select 1 from control_event_acks ack where ack.node_id=$1 and ack.event_id=event.id)
        order by event.created_at,event.id limit $3`, consumer.node, coverage, limit)
	if err != nil {
		return nil, ErrDatabaseUnavailable
	}
	events, err := readControlEvents(rows)
	if err != nil {
		return nil, err
	}
	if len(events) == 0 {
		if _, err := transaction.ExecContext(ctx, `update control_consumers set coverage=$3::pg_snapshot where node_id=$1 and generation=$2`, consumer.node, consumer.generation, next); err != nil {
			return nil, ErrDatabaseUnavailable
		}
		if _, err := transaction.ExecContext(ctx, `delete from control_event_acks where ctid in
            (select ack.ctid from control_event_acks ack join control_outbox event on ack.event_id=event.id where ack.node_id=$1 and pg_visible_in_snapshot(event.producer_xid,$2::pg_snapshot) limit 512)`, consumer.node, next); err != nil {
			return nil, ErrDatabaseUnavailable
		}
	}
	if err := transaction.Commit(); err != nil {
		return nil, ErrDatabaseUnavailable
	}
	return events, nil
}

func (consumer *ControlConsumer) MarkControlEventPublished(ctx context.Context, id string) error {
	if !grantUUIDPattern.MatchString(id) {
		return ErrGrantInvalid
	}
	transaction, err := consumer.postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return ErrDatabaseUnavailable
	}
	defer transaction.Rollback()
	coverage, err := consumer.lock(ctx, transaction)
	if err != nil {
		return err
	}
	var covered bool
	if err := transaction.QueryRowContext(ctx, `select pg_visible_in_snapshot(producer_xid,$2::pg_snapshot) from control_outbox where id=$1`, id, coverage).Scan(&covered); errors.Is(err, sql.ErrNoRows) {
		return ErrGrantInvalid
	} else if err != nil {
		return ErrDatabaseUnavailable
	}
	if !covered {
		if _, err := transaction.ExecContext(ctx, `insert into control_event_acks(node_id,event_id) values($1,$2) on conflict do nothing`, consumer.node, id); err != nil {
			return ErrDatabaseUnavailable
		}
		// Preserve the legacy first-local-publication marker for diagnostics only.
		// Node delivery and compaction never depend on this shared marker.
		if _, err := transaction.ExecContext(ctx, `update control_outbox set published_at=coalesce(published_at,clock_timestamp()) where id=$1`, id); err != nil {
			return ErrDatabaseUnavailable
		}
	}
	if err := transaction.Commit(); err != nil {
		return ErrDatabaseUnavailable
	}
	return nil
}

func (consumer *ControlConsumer) PruneEphemeral(ctx context.Context) error {
	_, err := consumer.postgres.DB.ExecContext(ctx, `delete from control_consumers where node_id in
        (select node_id from control_consumers where not durable and lease_until<clock_timestamp()-interval '10 minutes' order by lease_until limit 128)`)
	if err != nil {
		return ErrDatabaseUnavailable
	}
	return nil
}
