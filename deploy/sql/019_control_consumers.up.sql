-- Full top-level XIDs retain commit visibility independently of creation time
-- or sequence allocation. Existing rows are backfilled before new consumers.
alter table control_outbox add column producer_xid xid8 not null default pg_current_xact_id();
create index control_outbox_producer on control_outbox(producer_xid,created_at,id);

create function control_outbox_identity() returns trigger language plpgsql as $$
begin
    if tg_op='INSERT' then new.producer_xid=pg_current_xact_id();return new;end if;
    if row(new.id,new.org_id,new.topic,new.payload,new.created_at,new.producer_xid)
        is distinct from row(old.id,old.org_id,old.topic,old.payload,old.created_at,old.producer_xid) then
        raise exception 'control event identity and payload are immutable' using errcode='23514';
    end if;
    return new;
end $$;
create trigger control_outbox_identity before insert or update on control_outbox for each row execute function control_outbox_identity();

create table control_consumers (
    node_id uuid primary key,
    generation uuid not null,
    coverage pg_snapshot not null,
    durable boolean not null,
    lease_until timestamptz not null,
    created_at timestamptz not null default clock_timestamp(),
    renewed_at timestamptz not null default clock_timestamp()
);
create index control_consumers_ephemeral_expiry on control_consumers(lease_until) where not durable;

create table control_event_acks (
    node_id uuid not null references control_consumers(node_id) on delete cascade,
    event_id uuid not null references control_outbox(id) on delete cascade,
    applied_at timestamptz not null default clock_timestamp(),
    primary key(node_id,event_id)
);
comment on table control_event_acks is
    'Independent local-apply acknowledgements; one relay cannot consume another relay delivery. Compacted only behind that consumer snapshot.';
