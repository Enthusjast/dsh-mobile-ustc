begin;
create table remote_recovery_runs (
    id uuid primary key,
    source_epoch uuid not null,
    target_epoch uuid not null unique check (target_epoch<>source_epoch),
    phase text not null check (phase in ('quarantined','ready')),
    prepared_at timestamptz not null default clock_timestamp(),
    released_at timestamptz,
    authority_sha256 text check (authority_sha256 ~ '^[0-9a-f]{64}$'),
    counts jsonb not null check (jsonb_typeof(counts)='object'),
    check ((phase='ready')=(released_at is not null and authority_sha256 is not null))
);
create table remote_recovery_state (
    slot integer primary key check(slot=1),
    epoch uuid not null,
    phase text not null check(phase in ('ready','quarantined')),
    recovery_id uuid references remote_recovery_runs(id),
    token_not_before timestamptz,
    check(phase='ready' or recovery_id is not null)
);
-- Compatibility epoch for databases that have not undergone recovery. A
-- recovery must choose a new external deployment epoch before reopening.
insert into remote_recovery_state(slot,epoch,phase) values(1,'00000000-0000-4000-8000-000000000000','ready');
create table remote_recovery_memberships (
    recovery_id uuid not null references remote_recovery_runs(id),
    org_id uuid not null,
    user_id uuid not null,
    role text not null,
    primary key(recovery_id,org_id,user_id)
);
create function remote_database_epoch() returns uuid language sql stable as $$
    select epoch from remote_recovery_state where slot=1
$$;
alter table control_outbox add column database_epoch uuid not null default remote_database_epoch();
alter table control_consumers add column database_epoch uuid not null default remote_database_epoch();
drop index control_outbox_producer;
create index control_outbox_epoch_producer on control_outbox(database_epoch,producer_xid,created_at,id);
create or replace function control_outbox_identity() returns trigger language plpgsql as $$
begin
    if tg_op='INSERT' then
        new.producer_xid=pg_current_xact_id();new.database_epoch=remote_database_epoch();return new;
    end if;
    if row(new.id,new.org_id,new.topic,new.payload,new.created_at,new.producer_xid,new.database_epoch)
        is distinct from row(old.id,old.org_id,old.topic,old.payload,old.created_at,old.producer_xid,old.database_epoch) then
        raise exception 'control event identity and payload are immutable' using errcode='23514';
    end if;
    return new;
end $$;
commit;
