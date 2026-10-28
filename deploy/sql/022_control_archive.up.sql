begin;

create table control_archive_batches (
    id uuid primary key,
    database_epoch uuid not null,
    batch_limit integer not null check(batch_limit between 1 and 128),
    retention_years integer not null default 1 check(retention_years between 1 and 10),
    cutoff timestamptz not null,
    archived_at timestamptz not null,
    retain_until timestamptz not null,
    event_count integer not null check(event_count between 0 and 128),
    previous_epoch_count integer not null check(previous_epoch_count between 0 and event_count),
    check(cutoff<=archived_at-interval '2160 hours'),
    check(retain_until>=((archived_at at time zone 'UTC')+make_interval(years => retention_years)) at time zone 'UTC'),
    unique(id,database_epoch,archived_at,retain_until)
);

create table control_outbox_archive (
    event_id uuid primary key,
    batch_id uuid not null,
    batch_epoch uuid not null,
    database_epoch uuid not null,
    topic text not null,
    source_created_at timestamptz not null,
    source jsonb not null check(jsonb_typeof(source)='object'),
    reason text not null check(reason in ('covered','recovered_epoch')),
    archived_at timestamptz not null,
    retain_until timestamptz not null,
    check(source ?& array['id','database_epoch','topic','payload','created_at','published_at','producer_xid']),
    check((source->>'id'=event_id::text and source->>'database_epoch'=database_epoch::text and source->>'topic'=topic) is true),
    check((reason='covered' and database_epoch=batch_epoch) or (reason='recovered_epoch' and database_epoch<>batch_epoch)),
    check(retain_until>=((archived_at at time zone 'UTC')+interval '1 year') at time zone 'UTC'),
    foreign key(batch_id,batch_epoch,archived_at,retain_until)
        references control_archive_batches(id,database_epoch,archived_at,retain_until) deferrable initially deferred
);
create index control_outbox_archive_batch on control_outbox_archive(batch_id,event_id);
create index control_outbox_archive_epoch on control_outbox_archive(database_epoch,source_created_at,event_id);

-- Acknowledgements still present when an event moves must survive the source
-- row's ON DELETE CASCADE, including acknowledgements from a restored epoch.
-- They do not reference live consumers: ephemeral consumer rows can expire.
create table control_event_ack_archive (
    node_id uuid not null,
    event_id uuid not null references control_outbox_archive(event_id) on delete cascade,
    applied_at timestamptz not null,
    source jsonb not null check(jsonb_typeof(source)='object'),
    primary key(node_id,event_id),
    check(source ?& array['node_id','event_id','applied_at']),
    check((source->>'node_id'=node_id::text and source->>'event_id'=event_id::text) is true)
);
create index control_event_ack_archive_event on control_event_ack_archive(event_id,node_id);
create index control_outbox_retention on control_outbox(created_at,id)
    where topic in ('device.revoked','runtime_grant.updated','runtime_grant.revoked','approval.pending','approval.decided',
        'approval.ended','approval.result','approval.authorization.prepared','approval.device.revoked');

-- Also fence registration through older INSERT paths. Capture coverage AFTER
-- waiting for maintenance, not from a pre-wait VALUES/default expression.
create function control_consumer_archive_bootstrap() returns trigger language plpgsql as $$
declare current_epoch uuid; current_phase text;
begin
    perform pg_advisory_xact_lock_shared(1380012611,1);
    select epoch,phase into current_epoch,current_phase from remote_recovery_state where slot=1 for share;
    if current_phase is distinct from 'ready' then
        raise exception 'control consumer recovery is not ready' using errcode='23514';
    end if;
    new.database_epoch=current_epoch;
    new.coverage=pg_current_snapshot();
    return new;
end $$;
create trigger control_consumer_archive_bootstrap before insert on control_consumers
    for each row execute function control_consumer_archive_bootstrap();

-- Consumer deletion normally cascades acknowledgements. A post-recovery
-- consumer cannot discard old-epoch facts before they have been archived.
create function control_consumer_archive_delete_guard() returns trigger language plpgsql as $$
declare current_epoch uuid;
begin
    select epoch into current_epoch from remote_recovery_state where slot=1 for share;
    if current_epoch is null or exists(
        select 1 from control_event_acks a join control_outbox e on e.id=a.event_id
        where a.node_id=old.node_id and e.database_epoch<>current_epoch
    ) then
        raise exception 'consumer has unarchived old-epoch acknowledgements' using errcode='23514';
    end if;
    return old;
end $$;
create trigger control_consumer_archive_delete_guard before delete on control_consumers
    for each row execute function control_consumer_archive_delete_guard();

-- Source deletion is only safe after the exact source and all remaining acks
-- have been copied. This also protects unsupported topics from manual cleanup.
create function control_outbox_retention_guard() returns trigger language plpgsql as $$
begin
    if not exists(select 1 from control_outbox_archive h where h.event_id=old.id and h.source=to_jsonb(old)) or exists(
        select 1 from control_event_acks a where a.event_id=old.id and not exists(
            select 1 from control_event_ack_archive h where h.node_id=a.node_id and h.event_id=a.event_id and h.source=to_jsonb(a))
    ) then
        raise exception 'control event or acknowledgements are not archived' using errcode='23514';
    end if;
    return old;
end $$;
create trigger control_outbox_retention_guard before delete on control_outbox
    for each row execute function control_outbox_retention_guard();

-- Normal current-epoch checkpoint compaction remains allowed. A single
-- statement guard also covers direct old-epoch deletes and FK cascades.
create function control_hot_ack_retention_guard() returns trigger language plpgsql as $$
declare current_epoch uuid;
begin
    if not exists(select 1 from deleted_control_acks) then return null; end if;
    select epoch into current_epoch from remote_recovery_state where slot=1 for share;
    if current_epoch is null then
        raise exception 'control recovery state is unavailable' using errcode='23514';
    end if;
    -- The ordinary current-epoch compaction path needs only the parent event's
    -- epoch columns. Read archived ack payloads only when old/unknown rows exist.
    if exists(
        select 1 from deleted_control_acks a
        left join control_outbox e on e.id=a.event_id
        left join control_outbox_archive h on h.event_id=a.event_id
        where (coalesce(e.database_epoch,h.database_epoch) is null or coalesce(e.database_epoch,h.database_epoch)<>current_epoch)
    ) then
        if exists(
            select 1 from deleted_control_acks a
            left join control_outbox e on e.id=a.event_id
            left join control_outbox_archive h on h.event_id=a.event_id
            where (coalesce(e.database_epoch,h.database_epoch) is null or coalesce(e.database_epoch,h.database_epoch)<>current_epoch)
            and not exists(select 1 from control_event_ack_archive copied
                where copied.node_id=a.node_id and copied.event_id=a.event_id and copied.source=to_jsonb(a))
        ) then
            raise exception 'old-epoch acknowledgements are not archived' using errcode='23514';
        end if;
    end if;
    return null;
end $$;
create trigger control_hot_ack_retention_guard after delete on control_event_acks
    referencing old table as deleted_control_acks for each statement execute function control_hot_ack_retention_guard();

create function control_archive_no_truncate() returns trigger language plpgsql as $$
begin
    raise exception 'control history cannot be truncated' using errcode='23514';
end $$;
create trigger control_outbox_no_truncate before truncate on control_outbox for each statement execute function control_archive_no_truncate();
create trigger control_ack_no_truncate before truncate on control_event_acks for each statement execute function control_archive_no_truncate();
create trigger control_consumer_no_truncate before truncate on control_consumers for each statement execute function control_archive_no_truncate();
create trigger control_archive_batches_no_truncate before truncate on control_archive_batches for each statement execute function control_archive_no_truncate();
create trigger control_archive_events_no_truncate before truncate on control_outbox_archive for each statement execute function control_archive_no_truncate();
create trigger control_archive_acks_no_truncate before truncate on control_event_ack_archive for each statement execute function control_archive_no_truncate();

create function control_archive_immutable() returns trigger language plpgsql as $$
declare current_phase text;
begin
    if tg_op='UPDATE' or tg_table_name='control_archive_batches' then
        raise exception 'control archive history is immutable' using errcode='23514';
    end if;
    if old.retain_until>clock_timestamp() then
        raise exception 'control archive retention has not elapsed' using errcode='23514';
    end if;
    select phase into current_phase from remote_recovery_state where slot=1 for share;
    if current_phase is distinct from 'ready' then
        raise exception 'control archive recovery is not ready' using errcode='23514';
    end if;
    insert into audit_log(actor_type,actor_id,action,result,metadata)
    values('system',current_user,'control.archive.delete','success',
        jsonb_build_object('event_id',old.event_id,'batch_id',old.batch_id,'database_epoch',old.database_epoch,'db_session_user',session_user));
    return old;
end $$;
create trigger control_archive_batches_immutable before update or delete on control_archive_batches
    for each row execute function control_archive_immutable();
create trigger control_outbox_archive_immutable before update or delete on control_outbox_archive
    for each row execute function control_archive_immutable();

create function control_archive_ack_immutable() returns trigger language plpgsql as $$
begin
    -- Parent deletion already passed the retention/recovery/audit guard. Only
    -- its cascading delete may remove a copied acknowledgement.
    if tg_op='UPDATE' or exists(select 1 from control_outbox_archive where event_id=old.event_id) then
        raise exception 'control archive acknowledgement is immutable' using errcode='23514';
    end if;
    return old;
end $$;
create trigger control_archive_ack_immutable before update or delete on control_event_ack_archive
    for each row execute function control_archive_ack_immutable();
revoke all on control_archive_batches,control_outbox_archive,control_event_ack_archive from public;

commit;
