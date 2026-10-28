begin;

-- Existing source snapshots remain immutable; backfilled ownership is only a
-- sentinel, not a claim about their historical producer XIDs.
alter table control_archive_batches add column archive_xid xid8 not null default pg_current_xact_id();
alter table control_archive_batches add column archive_write_epoch uuid not null default remote_database_epoch();
alter table control_outbox_archive add column archive_xid xid8 not null default pg_current_xact_id();
alter table control_outbox_archive add column archive_write_epoch uuid not null default remote_database_epoch();
create function control_archive_write_owner() returns trigger language plpgsql as $$
begin
    new.archive_xid=pg_current_xact_id();
    new.archive_write_epoch=remote_database_epoch();
    return new;
end $$;
create trigger control_archive_batch_write_owner before insert on control_archive_batches
    for each row execute function control_archive_write_owner();
create trigger control_archive_write_owner before insert on control_outbox_archive
    for each row execute function control_archive_write_owner();

-- ArchiveControlEvents inserts the batch after its events; deferred guards
-- bind them to the same transaction and require its declared count to match.
create function control_archive_batch_event_guard() returns trigger language plpgsql as $$
declare owner_xid xid8; owner_epoch uuid; current_epoch uuid; expected_count integer; actual_count integer;
begin
    select epoch into current_epoch from remote_recovery_state where slot=1 for share;
    if tg_table_name='control_archive_batches' then
        select count(*) into actual_count from control_outbox_archive where batch_id=new.id;
        if actual_count<>new.event_count then raise exception 'archive batch count mismatch' using errcode='23514'; end if;
    else
        select archive_xid,archive_write_epoch into owner_xid,owner_epoch from control_archive_batches where id=new.batch_id;
        if owner_xid is null or current_epoch is null or owner_epoch<>current_epoch or owner_xid<>pg_current_xact_id() then
            raise exception 'archive event must be copied with its batch' using errcode='23514';
        end if;
    end if;
    return null;
end $$;
create constraint trigger control_archive_batch_event_guard after insert on control_archive_batches
    deferrable initially deferred for each row execute function control_archive_batch_event_guard();
create constraint trigger control_archive_batch_event_guard after insert on control_outbox_archive
    deferrable initially deferred for each row execute function control_archive_batch_event_guard();

-- Remaining acknowledgements can only be copied while their parent history
-- row is created. Never use a source-cluster XID in the current epoch.
create function control_archive_ack_insert_guard() returns trigger language plpgsql as $$
declare owner_xid xid8; owner_epoch uuid; current_epoch uuid;
begin
    select archive_xid,archive_write_epoch into owner_xid,owner_epoch from control_outbox_archive where event_id=new.event_id;
    select epoch into current_epoch from remote_recovery_state where slot=1 for share;
    if owner_xid is null or current_epoch is null or owner_epoch<>current_epoch or owner_xid<>pg_current_xact_id() then
        raise exception 'archive acknowledgement must be copied with its parent' using errcode='23514';
    end if;
    return new;
end $$;
create trigger control_archive_ack_insert_guard before insert on control_event_ack_archive
    for each row execute function control_archive_ack_insert_guard();

create table control_archive_exports (
    id uuid primary key,
    domain_id uuid not null,
    operation_epoch uuid not null,
    batch_id uuid not null references control_archive_batches(id),
    key_id text not null check(key_id ~ '^[A-Za-z0-9_-]{1,32}$'),
    key_fingerprint text not null check(key_fingerprint ~ '^[0-9a-f]{64}$'),
    destination_fingerprint text not null check(destination_fingerprint ~ '^[0-9a-f]{64}$'),
    salt bytea not null check(octet_length(salt)=32),
    nonce bytea not null check(octet_length(nonce)=12),
    payload_sha256 text not null check(payload_sha256 ~ '^[0-9a-f]{64}$'),
    artifact_sha256 text not null check(artifact_sha256 ~ '^[0-9a-f]{64}$'),
    artifact_size integer not null check(artifact_size between 76 and 8388684),
    event_count integer not null check(event_count between 0 and 128),
    acknowledgement_count integer not null check(acknowledgement_count between 0 and 8192),
    prepared_at timestamptz not null,
    state text not null check(state in ('prepared','published','aborted')),
    completed_at timestamptz,
    check((state='prepared' and completed_at is null) or (state in ('published','aborted') and completed_at is not null and completed_at>=prepared_at)),
    unique(key_fingerprint,salt)
);
create index control_archive_exports_batch on control_archive_exports(batch_id,state);

create function control_archive_export_guard() returns trigger language plpgsql as $$
declare current_epoch uuid; current_phase text; expected_count integer; permitted boolean;
begin
    if tg_op='DELETE' then raise exception 'archive export history is immutable' using errcode='23514'; end if;
    select epoch,phase into current_epoch,current_phase from remote_recovery_state where slot=1 for share;
    if current_phase is distinct from 'ready' then
        raise exception 'archive export recovery is not ready' using errcode='23514';
    end if;
    if current_epoch<>new.operation_epoch then
        permitted=false;
        if tg_op='UPDATE' and old.state='prepared' and new.state='aborted' then
            with recursive lineage(epoch) as (
                select old.operation_epoch union
                select r.target_epoch from remote_recovery_runs r join lineage l on r.source_epoch=l.epoch where r.phase='ready'
            ) select exists(select 1 from lineage where epoch=current_epoch) into permitted;
        end if;
        if not permitted then raise exception 'archive export epoch is fenced' using errcode='23514'; end if;
    end if;
    if tg_op='INSERT' then
        select event_count into expected_count from control_archive_batches where id=new.batch_id;
        if expected_count is null or expected_count<>new.event_count or new.state<>'prepared' then
            raise exception 'archive export preparation is invalid' using errcode='23514';
        end if;
        return new;
    end if;
    if row(new.id,new.domain_id,new.operation_epoch,new.batch_id,new.key_id,new.key_fingerprint,new.destination_fingerprint,new.salt,new.nonce,new.payload_sha256,new.artifact_sha256,new.artifact_size,new.event_count,new.acknowledgement_count,new.prepared_at)
        is distinct from row(old.id,old.domain_id,old.operation_epoch,old.batch_id,old.key_id,old.key_fingerprint,old.destination_fingerprint,old.salt,old.nonce,old.payload_sha256,old.artifact_sha256,old.artifact_size,old.event_count,old.acknowledgement_count,old.prepared_at)
        or old.state<>'prepared' or new.state not in ('published','aborted') or new.completed_at is null then
        raise exception 'archive export identity or transition is invalid' using errcode='23514';
    end if;
    return new;
end $$;
create trigger control_archive_export_guard before insert or update or delete on control_archive_exports
    for each row execute function control_archive_export_guard();
create trigger control_archive_exports_no_truncate before truncate on control_archive_exports
    for each statement execute function control_archive_no_truncate();

-- An unfinished export pins the source batch even after its retention deadline.
-- A verified file or explicit audited abort releases it; no timeout silently does.
create or replace function control_archive_immutable() returns trigger language plpgsql as $$
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
    if exists(select 1 from control_archive_exports where batch_id=old.batch_id and state='prepared') then
        raise exception 'control archive export is unfinished' using errcode='23514';
    end if;
    insert into audit_log(actor_type,actor_id,action,result,metadata)
    values('system',current_user,'control.archive.delete','success',
        jsonb_build_object('event_id',old.event_id,'batch_id',old.batch_id,'database_epoch',old.database_epoch,'db_session_user',session_user));
    return old;
end $$;
revoke all on control_archive_exports from public;
commit;
