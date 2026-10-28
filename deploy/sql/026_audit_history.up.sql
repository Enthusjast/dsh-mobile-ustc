begin;

-- Earlier rows cannot be reliably attributed to a database epoch: a backup
-- may already have been restored before this migration. Preserve NULL for them.
alter table audit_log add column database_epoch uuid;
alter table audit_log add column producer_xid xid8;
create function audit_log_stamp() returns trigger language plpgsql as $$
begin
    new.ts=clock_timestamp();
    new.database_epoch=remote_database_epoch();
    if new.database_epoch is null then raise exception 'audit database epoch is unavailable' using errcode='23514'; end if;
    new.producer_xid=pg_current_xact_id();
    return new;
end $$;
create trigger audit_log_stamp before insert on audit_log for each row execute function audit_log_stamp();
create index audit_log_archive_candidates on audit_log(ts,id);

create table audit_archive_batches (
    id uuid primary key,
    database_epoch uuid not null,
    batch_limit integer not null check(batch_limit between 1 and 128),
    retention_years integer not null check(retention_years between 1 and 10),
    cutoff timestamptz not null,
    archived_at timestamptz not null,
    retain_until timestamptz not null,
    entry_count integer not null check(entry_count between 0 and batch_limit),
    archive_xid xid8 not null default pg_current_xact_id(),
    unique(id,database_epoch),
    check(cutoff<=archived_at-interval '2160 hours'),
    check(retain_until>=((archived_at at time zone 'UTC')+make_interval(years=>retention_years)) at time zone 'UTC')
);
create table audit_log_archive (
    source_id bigint primary key,
    batch_id uuid not null,
    batch_epoch uuid not null,
    source_epoch uuid,
    source_ts timestamptz not null,
    source jsonb not null check(jsonb_typeof(source)='object' and octet_length(source::text)<=262144),
    archive_xid xid8 not null default pg_current_xact_id(),
    foreign key(batch_id,batch_epoch) references audit_archive_batches(id,database_epoch) deferrable initially deferred
);
create index audit_log_archive_batch on audit_log_archive(batch_id);

create function audit_archive_batch_guard() returns trigger language plpgsql as $$
declare current_epoch uuid; current_phase text;
begin
    if tg_op<>'INSERT' then raise exception 'audit archive batch is immutable' using errcode='23514'; end if;
    select epoch,phase into current_epoch,current_phase from remote_recovery_state where slot=1 for share;
    if current_phase is distinct from 'ready' or current_epoch is distinct from new.database_epoch then
        raise exception 'audit archive epoch is not ready' using errcode='23514';
    end if;
    new.archived_at=clock_timestamp();
    new.cutoff=new.archived_at-interval '2160 hours';
    new.retain_until=((new.archived_at at time zone 'UTC')+make_interval(years=>new.retention_years)) at time zone 'UTC';
    new.archive_xid=pg_current_xact_id();
    return new;
end $$;
create trigger audit_archive_batch_guard before insert or update or delete on audit_archive_batches
    for each row execute function audit_archive_batch_guard();

create function audit_archive_entry_guard() returns trigger language plpgsql as $$
declare batch audit_archive_batches%rowtype; source_row audit_log%rowtype; current_epoch uuid; current_phase text;
begin
    if tg_op='UPDATE' then raise exception 'audit archive entry is immutable' using errcode='23514'; end if;
    select * into batch from audit_archive_batches where id=case when tg_op='INSERT' then new.batch_id else old.batch_id end;
    select epoch,phase into current_epoch,current_phase from remote_recovery_state where slot=1 for share;
    if batch.id is null or current_phase is distinct from 'ready' then raise exception 'audit archive is unavailable' using errcode='23514'; end if;
    if tg_op='DELETE' then
        if batch.retain_until>clock_timestamp() then raise exception 'audit archive retention has not elapsed' using errcode='23514'; end if;
        insert into audit_log(actor_type,actor_id,action,result,metadata)
        values('system',current_user,'audit.archive.delete','success',
            jsonb_build_object('batch_id',batch.id,'source_id',old.source_id,'source_epoch',old.source_epoch,'current_epoch',current_epoch,'db_session_user',session_user));
        return old;
    end if;
    if batch.archive_xid<>pg_current_xact_id() or batch.database_epoch<>current_epoch or new.batch_epoch<>batch.database_epoch then
        raise exception 'audit archive entry must be created with its batch' using errcode='23514';
    end if;
    select * into source_row from audit_log where id=new.source_id for update;
    if source_row.id is null or source_row.ts>batch.cutoff or new.source_ts is distinct from source_row.ts
       or new.source_epoch is distinct from source_row.database_epoch or new.source is distinct from to_jsonb(source_row) then
        raise exception 'audit archive does not match its source' using errcode='23514';
    end if;
    new.archive_xid=pg_current_xact_id();
    return new;
end $$;
create trigger audit_archive_entry_guard before insert or update or delete on audit_log_archive
    for each row execute function audit_archive_entry_guard();

create function audit_log_immutable() returns trigger language plpgsql as $$
declare copied audit_log_archive%rowtype; batch audit_archive_batches%rowtype;
begin
    if tg_op='UPDATE' then raise exception 'audit history is immutable' using errcode='23514'; end if;
    select * into copied from audit_log_archive where source_id=old.id;
    select * into batch from audit_archive_batches where id=copied.batch_id;
    if copied.source_id is null or batch.id is null or copied.archive_xid<>pg_current_xact_id() or batch.archive_xid<>pg_current_xact_id()
       or copied.source is distinct from to_jsonb(old) or old.ts>batch.cutoff
       or not exists(select 1 from audit_log a where a.action='audit.archive.batch' and a.actor_type='system'
           and a.database_epoch=batch.database_epoch and a.producer_xid=pg_current_xact_id() and a.metadata->>'batch_id'=batch.id::text) then
        raise exception 'audit history requires an exact audited archive copy' using errcode='23514';
    end if;
    return old;
end $$;
create trigger audit_log_immutable before update or delete on audit_log for each row execute function audit_log_immutable();

create function audit_archive_complete_guard() returns trigger language plpgsql as $$
declare actual_count integer; source_remaining boolean;
begin
    select count(*),coalesce(bool_or(a.id is not null),false) into actual_count,source_remaining
      from audit_log_archive h left join audit_log a on a.id=h.source_id where h.batch_id=new.id;
    if actual_count<>new.entry_count or source_remaining
       or not exists(select 1 from audit_log a where a.action='audit.archive.batch' and a.actor_type='system'
           and a.database_epoch=new.database_epoch and a.producer_xid=pg_current_xact_id() and a.metadata->>'batch_id'=new.id::text) then
        raise exception 'audit archive batch is incomplete or unaudited' using errcode='23514';
    end if;
    return null;
end $$;
create constraint trigger audit_archive_complete_guard after insert on audit_archive_batches
    deferrable initially deferred for each row execute function audit_archive_complete_guard();
create trigger audit_log_no_truncate before truncate on audit_log for each statement execute function control_archive_no_truncate();
create trigger audit_archive_batches_no_truncate before truncate on audit_archive_batches for each statement execute function control_archive_no_truncate();
create trigger audit_log_archive_no_truncate before truncate on audit_log_archive for each statement execute function control_archive_no_truncate();
revoke all on audit_archive_batches,audit_log_archive from public;
commit;
