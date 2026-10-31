begin;
lock table commands,file_message_refs in share row exclusive mode;

-- Only the request identity survives expiry; this table holds no body/digest/result.
create table command_keys(device_id uuid not null,request_id uuid not null,primary key(device_id,request_id));
insert into command_keys select device_id,request_id from commands;
create function command_keys_immutable() returns trigger language plpgsql as $$
begin raise exception 'command identities cannot be removed or changed' using errcode='23514'; end $$;
create trigger command_keys_immutable before update or delete on command_keys for each row execute function command_keys_immutable();
create trigger command_keys_no_truncate before truncate on command_keys for each statement execute function command_keys_immutable();
create function command_key_owner() returns trigger language plpgsql as $$
declare inserted uuid;
begin
    if tg_op='UPDATE' then
        if row(new.device_id,new.request_id) is distinct from row(old.device_id,old.request_id) then
            raise exception 'command identity is immutable' using errcode='23514';
        end if;
        return new;
    end if;
    insert into command_keys(device_id,request_id) values(new.device_id,new.request_id) on conflict do nothing returning request_id into inserted;
    if inserted is null then
        -- Keep an existing live duplicate pinned until ON CONFLICT has run.
        perform 1 from commands where device_id=new.device_id and request_id=new.request_id for update;
        if not found then raise exception 'command identity has retired from the active ledger' using errcode='23514'; end if;
    end if;
    return new;
end $$;
create trigger command_key_owner before insert or update on commands for each row execute function command_key_owner();
alter table commands add constraint commands_key_fk foreign key(device_id,request_id) references command_keys(device_id,request_id);
alter table file_message_refs drop constraint file_message_refs_device_id_request_id_fkey;
alter table file_message_refs add constraint file_message_refs_key_fk foreign key(device_id,request_id) references command_keys(device_id,request_id);

create table command_archive_batches (
    id uuid primary key,database_epoch uuid not null,
    batch_limit integer not null check(batch_limit between 1 and 128),
    hot_days integer not null check(hot_days between 1 and 3650),
    cold_days integer not null check(cold_days between 0 and 3650),
    cutoff timestamptz not null,archived_at timestamptz not null,retain_until timestamptz not null,
    entry_count integer not null check(entry_count between 0 and batch_limit),
    archive_xid xid8 not null default pg_current_xact_id(),unique(id,database_epoch),
    check(cutoff<=archived_at-make_interval(hours=>hot_days*24)),
    check(retain_until>=archived_at+make_interval(hours=>cold_days*24))
);
create table command_archive (
    like commands including defaults including constraints,
    batch_id uuid not null references command_archive_batches(id),
    source jsonb not null check(jsonb_typeof(source)='object' and octet_length(source::text)<=65536),
    archive_xid xid8 not null default pg_current_xact_id(),
    primary key(device_id,request_id),
    foreign key(device_id,request_id) references command_keys(device_id,request_id),
    check(state in ('settled','rejected'))
);
create index command_archive_batch on command_archive(batch_id);
create index commands_archive_candidates on commands(updated_at,device_id,request_id) where state in ('settled','rejected');
create view command_records with (security_invoker=true) as
    select device_id,request_id,user_id,runtime_id,session_id,payload_sha256,state,updated_at,created_at,workspace_id,action,child_session_id,fork_outcome from commands
    union all
    select device_id,request_id,user_id,runtime_id,session_id,payload_sha256,state,updated_at,created_at,workspace_id,action,child_session_id,fork_outcome from command_archive;

create function command_archive_batch_guard() returns trigger language plpgsql as $$
declare current_epoch uuid; current_phase text;
begin
    if tg_op<>'INSERT' then raise exception 'command archive batch is immutable' using errcode='23514'; end if;
    select epoch,phase into current_epoch,current_phase from remote_recovery_state where slot=1 for share;
    if current_phase is distinct from 'ready' or current_epoch is distinct from new.database_epoch then
        raise exception 'command archive recovery is fenced' using errcode='23514';
    end if;
    new.archived_at=clock_timestamp();new.cutoff=new.archived_at-make_interval(hours=>new.hot_days*24);
    new.retain_until=new.archived_at+make_interval(hours=>new.cold_days*24);
    new.archive_xid=pg_current_xact_id();return new;
end $$;
create trigger command_archive_batch_guard before insert or update or delete on command_archive_batches for each row execute function command_archive_batch_guard();
create function command_archive_entry_guard() returns trigger language plpgsql as $$
declare batch command_archive_batches%rowtype; item commands%rowtype; current_epoch uuid; current_phase text; audit_id bigint;
begin
    if tg_op='UPDATE' then raise exception 'command archive entry is immutable' using errcode='23514'; end if;
    select * into batch from command_archive_batches where id=case when tg_op='INSERT' then new.batch_id else old.batch_id end;
    select epoch,phase into current_epoch,current_phase from remote_recovery_state where slot=1 for share;
    if batch.id is null or current_phase is distinct from 'ready' then raise exception 'command archive is unavailable' using errcode='23514'; end if;
    if tg_op='DELETE' then
        if current_setting('transaction_isolation')<>'read committed' or batch.retain_until>clock_timestamp()
           or exists(select 1 from file_message_refs where device_id=old.device_id and request_id=old.request_id) then
            raise exception 'command archive retention or file reference prevents deletion' using errcode='23514';
        end if;
        insert into audit_log(actor_type,actor_id,action,result,metadata)
        values('system',current_user,'command.archive.delete','success',jsonb_build_object('batch_id',batch.id,
            'device_id',old.device_id,'request_id',old.request_id,'batch_epoch',batch.database_epoch,'current_epoch',current_epoch,'db_session_user',session_user)) returning id into audit_id;
        if audit_id is null then raise exception 'command archive deletion audit is unavailable' using errcode='23514'; end if;
        return old;
    end if;
    if batch.archive_xid<>pg_current_xact_id() or batch.database_epoch<>current_epoch then raise exception 'command archive write is fenced' using errcode='23514'; end if;
    select * into item from commands where device_id=new.device_id and request_id=new.request_id for update;
    if item.device_id is null or item.state not in ('settled','rejected') or item.created_at>batch.cutoff or item.updated_at>batch.cutoff
       or new.source is distinct from to_jsonb(item)
       or to_jsonb(new)-array['batch_id','source','archive_xid'] is distinct from to_jsonb(item) then
        raise exception 'command archive does not match an eligible source' using errcode='23514';
    end if;
    new.archive_xid=pg_current_xact_id();return new;
end $$;
create trigger command_archive_entry_guard before insert or update or delete on command_archive for each row execute function command_archive_entry_guard();
create function command_archive_delete_guard() returns trigger language plpgsql as $$
begin
    if not exists(select 1 from command_archive h join command_archive_batches b on b.id=h.batch_id
        where h.device_id=old.device_id and h.request_id=old.request_id and h.source=to_jsonb(old)
        and h.archive_xid=pg_current_xact_id() and b.archive_xid=pg_current_xact_id()
        and exists(select 1 from audit_log a where a.action='command.archive.batch' and a.actor_type='system'
            and a.database_epoch=b.database_epoch and a.producer_xid=pg_current_xact_id() and a.metadata->>'batch_id'=b.id::text)) then
        raise exception 'command removal requires an exact audited archive copy' using errcode='23514';
    end if;
    return old;
end $$;
create trigger command_archive_delete_guard before delete on commands for each row execute function command_archive_delete_guard();
create function command_archive_complete_guard() returns trigger language plpgsql as $$
declare actual_count integer; source_remaining boolean;
begin
    select count(*),coalesce(bool_or(c.device_id is not null),false) into actual_count,source_remaining
      from command_archive h left join commands c using(device_id,request_id) where h.batch_id=new.id;
    if actual_count<>new.entry_count or source_remaining or not exists(select 1 from audit_log a
        where a.action='command.archive.batch' and a.actor_type='system' and a.database_epoch=new.database_epoch
        and a.producer_xid=pg_current_xact_id() and a.metadata->>'batch_id'=new.id::text) then
        raise exception 'command archive batch is incomplete or unaudited' using errcode='23514';
    end if;
    return null;
end $$;
create constraint trigger command_archive_complete_guard after insert on command_archive_batches deferrable initially deferred for each row execute function command_archive_complete_guard();
create function file_message_command_owner() returns trigger language plpgsql as $$
begin
    perform 1 from commands where device_id=new.device_id and request_id=new.request_id for key share;
    if not found then
        perform 1 from command_archive where device_id=new.device_id and request_id=new.request_id for key share;
        if not found then raise exception 'file message command metadata is unavailable' using errcode='23514'; end if;
    end if;
    return new;
end $$;
create trigger file_message_command_owner before insert or update on file_message_refs for each row execute function file_message_command_owner();
create trigger commands_no_truncate before truncate on commands for each statement execute function control_archive_no_truncate();
create trigger command_archive_no_truncate before truncate on command_archive for each statement execute function control_archive_no_truncate();
create trigger command_archive_batches_no_truncate before truncate on command_archive_batches for each statement execute function control_archive_no_truncate();
revoke all on command_keys,command_archive_batches,command_archive,command_records from public;
commit;
