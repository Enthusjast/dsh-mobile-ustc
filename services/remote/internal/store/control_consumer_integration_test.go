package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

const controlNodeA = "aaaaaaaa-1111-4111-8111-111111111111"
const controlNodeB = "bbbbbbbb-1111-4111-8111-111111111111"
const controlDevice = "dddddddd-1111-4111-8111-111111111111"

func insertConsumerEvent(t *testing.T, ctx context.Context, connection interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) string {
	t.Helper()
	var id string
	if err := connection.QueryRowContext(ctx, `insert into control_outbox(topic,payload) values('device.revoked',jsonb_build_object('device_id',$1::text)) returning id::text`, controlDevice).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func consumerPendingIDs(t *testing.T, ctx context.Context, consumer *ControlConsumer, limit int) map[string]bool {
	t.Helper()
	events, err := consumer.PendingControlEvents(ctx, limit)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, event := range events {
		ids[event.ID] = true
	}
	return ids
}

func TestControlConsumersAcknowledgeIndependentlyAndCompactSafely(t *testing.T) {
	ctx, postgres := newPostgresIntegrationDatabase(t)
	old := insertConsumerEvent(t, ctx, postgres.DB)
	a, err := postgres.NewControlConsumer(ctx, controlNodeA)
	if err != nil {
		t.Fatal(err)
	}
	b, err := postgres.NewControlConsumer(ctx, controlNodeB)
	if err != nil {
		t.Fatal(err)
	}
	if got := consumerPendingIDs(t, ctx, a, 128); got[old] || len(got) != 0 {
		t.Fatal("fresh node replayed already-visible history")
	}
	first, second := insertConsumerEvent(t, ctx, postgres.DB), insertConsumerEvent(t, ctx, postgres.DB)
	if got := consumerPendingIDs(t, ctx, a, 1); len(got) != 1 || !got[first] {
		t.Fatal("batch did not preserve pending coverage", got)
	}
	if err := a.MarkControlEventPublished(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := a.MarkControlEventPublished(ctx, first); err != nil {
		t.Fatal("duplicate acknowledgement failed", err)
	}
	var published bool
	if err := postgres.DB.QueryRowContext(ctx, `select published_at is not null from control_outbox where id=$1`, first).Scan(&published); err != nil || !published {
		t.Fatal("legacy local marker missing", err)
	}
	if got := consumerPendingIDs(t, ctx, b, 128); len(got) != 2 || !got[first] || !got[second] {
		t.Fatal("one node consumed another node's delivery", got)
	}
	if got := consumerPendingIDs(t, ctx, a, 128); len(got) != 1 || !got[second] {
		t.Fatal("own acknowledgement was not isolated", got)
	}
	if err := a.MarkControlEventPublished(ctx, second); err != nil {
		t.Fatal(err)
	}
	if got := consumerPendingIDs(t, ctx, a, 128); len(got) != 0 {
		t.Fatal("acknowledged events replayed", got)
	}
	var count int
	if err := postgres.DB.QueryRowContext(ctx, `select count(*) from control_event_acks where node_id=$1`, controlNodeA).Scan(&count); err != nil || count != 0 {
		t.Fatal("covered acknowledgements did not compact", count, err)
	}
	if got := consumerPendingIDs(t, ctx, b, 128); len(got) != 2 {
		t.Fatal("another node checkpoint discarded backlog", got)
	}
}

func TestControlConsumerIncludesOldTimestampAndLateCommitAfterCheckpoint(t *testing.T) {
	ctx, postgres := newPostgresIntegrationDatabase(t)
	slow, err := postgres.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer slow.Rollback()
	if _, err := slow.ExecContext(ctx, `savepoint nested_event`); err != nil {
		t.Fatal(err)
	}
	var late string
	if err := slow.QueryRowContext(ctx, `insert into control_outbox(topic,payload,created_at,producer_xid) values('device.revoked',jsonb_build_object('device_id',$1::text),'2000-01-01','1'::xid8) returning id::text`, controlDevice).Scan(&late); err != nil {
		t.Fatal(err)
	}
	var producer, top string
	if err := slow.QueryRowContext(ctx, `select producer_xid::text,pg_current_xact_id()::text from control_outbox where id=$1`, late).Scan(&producer, &top); err != nil || producer != top {
		t.Fatal("event stored a subtransaction instead of full producer identity", producer, top, err)
	}
	a, err := postgres.NewControlConsumer(ctx, controlNodeA)
	if err != nil {
		t.Fatal(err)
	}
	fast := insertConsumerEvent(t, ctx, postgres.DB)
	if got := consumerPendingIDs(t, ctx, a, 128); len(got) != 1 || !got[fast] {
		t.Fatal("uncommitted producer leaked", got)
	}
	if err := a.MarkControlEventPublished(ctx, fast); err != nil {
		t.Fatal(err)
	}
	if got := consumerPendingIDs(t, ctx, a, 128); len(got) != 0 {
		t.Fatal("checkpoint did not finish committed work")
	}
	if _, err := slow.ExecContext(ctx, `release savepoint nested_event`); err != nil {
		t.Fatal(err)
	}
	if err := slow.Commit(); err != nil {
		t.Fatal(err)
	}
	if got := consumerPendingIDs(t, ctx, a, 128); len(got) != 1 || !got[late] {
		t.Fatal("checkpoint skipped a producer that committed late", got)
	}
}

func TestControlConsumerRestartReplaysUnackedAndFencesOldGeneration(t *testing.T) {
	ctx, postgres := newPostgresIntegrationDatabase(t)
	a, err := postgres.NewControlConsumer(ctx, controlNodeA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.NewControlConsumer(ctx, controlNodeA); !errors.Is(err, ErrControlConsumerInUse) {
		t.Fatal("duplicate live ownership accepted", err)
	}
	acked, pending := insertConsumerEvent(t, ctx, postgres.DB), insertConsumerEvent(t, ctx, postgres.DB)
	if err := a.MarkControlEventPublished(ctx, acked); err != nil {
		t.Fatal(err)
	}
	if err := a.Release(ctx); err != nil {
		t.Fatal(err)
	}
	offline := insertConsumerEvent(t, ctx, postgres.DB)
	restarted, err := postgres.NewControlConsumer(ctx, controlNodeA)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.generation == a.generation {
		t.Fatal("restart reused an incarnation")
	}
	if got := consumerPendingIDs(t, ctx, restarted, 128); len(got) != 2 || got[acked] || !got[pending] || !got[offline] {
		t.Fatal("restart lost or repeated an independent acknowledgement", got)
	}
	if err := a.Renew(ctx); !errors.Is(err, ErrControlConsumerFenced) {
		t.Fatal("old generation renewed", err)
	}
	if _, err := a.PendingControlEvents(ctx, 128); !errors.Is(err, ErrControlConsumerFenced) {
		t.Fatal("old generation fetched", err)
	}
	if err := a.MarkControlEventPublished(ctx, pending); !errors.Is(err, ErrControlConsumerFenced) {
		t.Fatal("old generation acknowledged", err)
	}
	if err := a.Release(ctx); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Renew(ctx); err != nil {
		t.Fatal("old generation released new ownership", err)
	}
}

func TestControlConsumerFailedAckPreservesBacklogAndExpiredOwnerCannotRevive(t *testing.T) {
	ctx, postgres := newPostgresIntegrationDatabase(t)
	a, err := postgres.NewControlConsumer(ctx, controlNodeA)
	if err != nil {
		t.Fatal(err)
	}
	id := insertConsumerEvent(t, ctx, postgres.DB)
	for _, query := range []string{`create function fail_control_ack() returns trigger language plpgsql as $$ begin raise exception 'fixture ack unavailable';end $$`,
		`create trigger fail_control_ack before insert on control_event_acks for each row execute function fail_control_ack()`} {
		if _, err := postgres.DB.ExecContext(ctx, query); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.MarkControlEventPublished(ctx, id); !errors.Is(err, ErrDatabaseUnavailable) {
		t.Fatal("failed ack appeared successful", err)
	}
	if got := consumerPendingIDs(t, ctx, a, 128); !got[id] {
		t.Fatal("failed acknowledgement lost event")
	}
	var marked bool
	if err := postgres.DB.QueryRowContext(ctx, `select published_at is not null from control_outbox where id=$1`, id).Scan(&marked); err != nil || marked {
		t.Fatal("failed ack leaked global publication", err)
	}
	if _, err := postgres.DB.ExecContext(ctx, `drop trigger fail_control_ack on control_event_acks;update control_consumers set lease_until=clock_timestamp()-interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	if err := a.Renew(ctx); !errors.Is(err, ErrControlConsumerFenced) {
		t.Fatal("expired ownership revived", err)
	}
	if err := a.MarkControlEventPublished(ctx, id); !errors.Is(err, ErrControlConsumerFenced) {
		t.Fatal("expired owner acknowledged", err)
	}
	restarted, err := postgres.NewControlConsumer(ctx, controlNodeA)
	if err != nil {
		t.Fatal(err)
	}
	if got := consumerPendingIDs(t, ctx, restarted, 128); !got[id] {
		t.Fatal("reclaimed owner lost backlog")
	}
}

func TestControlConsumerPrunesOnlyExpiredEphemeralIncarnations(t *testing.T) {
	ctx, postgres := newPostgresIntegrationDatabase(t)
	durable, err := postgres.NewControlConsumer(ctx, controlNodeA)
	if err != nil {
		t.Fatal(err)
	}
	ephemeral, err := postgres.NewControlConsumer(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.DB.ExecContext(ctx, `update control_consumers set lease_until=clock_timestamp()-interval '20 minutes'`); err != nil {
		t.Fatal(err)
	}
	if err := durable.PruneEphemeral(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := postgres.DB.QueryRowContext(ctx, `select count(*) from control_consumers`).Scan(&count); err != nil || count != 1 {
		t.Fatal("unexpected consumer retirement", count, err)
	}
	if _, err := ephemeral.PendingControlEvents(ctx, 128); !errors.Is(err, ErrControlConsumerFenced) {
		t.Fatal("retired ephemeral owner remained usable", err)
	}
	if _, err := postgres.NewControlConsumer(ctx, controlNodeA); err != nil {
		t.Fatal("durable cursor was deleted", err)
	}
}

func TestControlConsumerCompactionIsBoundedAndEventIdentityImmutable(t *testing.T) {
	ctx, postgres := newPostgresIntegrationDatabase(t)
	a, err := postgres.NewControlConsumer(ctx, controlNodeA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.DB.ExecContext(ctx, `with inserted as (insert into control_outbox(topic,payload) select 'device.revoked',jsonb_build_object('device_id',$1::text) from generate_series(1,520) returning id)
        insert into control_event_acks(node_id,event_id) select $2,id from inserted`, controlDevice, controlNodeA); err != nil {
		t.Fatal(err)
	}
	if got := consumerPendingIDs(t, ctx, a, 128); len(got) != 0 {
		t.Fatal("acknowledged bulk delivery remained pending")
	}
	var count int
	if err := postgres.DB.QueryRowContext(ctx, `select count(*) from control_event_acks where node_id=$1`, controlNodeA).Scan(&count); err != nil || count != 8 {
		t.Fatal("compaction exceeded its bounded delete", count, err)
	}
	if got := consumerPendingIDs(t, ctx, a, 128); len(got) != 0 {
		t.Fatal("checkpoint compacted before covering events")
	}
	if err := postgres.DB.QueryRowContext(ctx, `select count(*) from control_event_acks where node_id=$1`, controlNodeA).Scan(&count); err != nil || count != 0 {
		t.Fatal("remaining covered acknowledgements leaked", count, err)
	}
	if _, err := postgres.DB.ExecContext(ctx, `update control_outbox set payload='{}'::jsonb`); err == nil {
		t.Fatal("covered control payload was mutable")
	}
	if _, err := postgres.DB.ExecContext(ctx, `update control_outbox set producer_xid=pg_current_xact_id()`); err == nil {
		t.Fatal("covered producer identity was mutable")
	}
}
