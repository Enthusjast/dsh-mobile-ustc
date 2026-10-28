begin;

-- Import identities remain after payload expiry so a retry cannot resurrect
-- deleted history or silently bind an old operation to a new database epoch.
create table control_archive_imports (
    id uuid primary key,
    domain_id uuid not null,
    export_id uuid not null,
    batch_id uuid not null,
    batch_epoch uuid not null,
    source_epoch uuid not null,
    target_epoch uuid not null,
    key_id text not null check(key_id ~ '^[A-Za-z0-9_-]{1,32}$'),
    key_fingerprint text not null check(key_fingerprint ~ '^[0-9a-f]{64}$'),
    artifact_sha256 text not null check(artifact_sha256 ~ '^[0-9a-f]{64}$'),
    artifact_size integer not null check(artifact_size between 76 and 8388684),
    payload_sha256 text not null check(payload_sha256 ~ '^[0-9a-f]{64}$'),
    event_count integer not null check(event_count between 0 and 128),
    acknowledgement_count integer not null check(acknowledgement_count between 0 and 8192),
    retain_until timestamptz not null,
    imported_at timestamptz not null,
    import_xid xid8 not null default pg_current_xact_id(),
    unique(domain_id,export_id)
);

create table control_archive_import_payloads (
    import_id uuid primary key references control_archive_imports(id),
    payload jsonb not null check(jsonb_typeof(payload)='object' and octet_length(payload::text)<=16777216)
);

create function control_archive_import_guard() returns trigger language plpgsql as $$
declare current_epoch uuid; current_phase text;
begin
    if tg_op<>'INSERT' then raise exception 'archive import identity is immutable' using errcode='23514'; end if;
    select epoch,phase into current_epoch,current_phase from remote_recovery_state where slot=1 for share;
    if current_phase is distinct from 'ready' or current_epoch is distinct from new.target_epoch then
        raise exception 'archive import epoch is not ready' using errcode='23514';
    end if;
    new.import_xid=pg_current_xact_id();
    return new;
end $$;
create trigger control_archive_import_guard before insert or update or delete on control_archive_imports
    for each row execute function control_archive_import_guard();

create function control_archive_import_complete_guard() returns trigger language plpgsql as $$
begin
    if not exists(select 1 from control_archive_import_payloads where import_id=new.id) then
        raise exception 'archive import payload is missing' using errcode='23514';
    end if;
    return null;
end $$;
create constraint trigger control_archive_import_complete_guard after insert on control_archive_imports
    deferrable initially deferred for each row execute function control_archive_import_complete_guard();

create function control_archive_import_payload_guard() returns trigger language plpgsql as $$
declare item control_archive_imports%rowtype; current_epoch uuid; current_phase text; ack_count bigint;
begin
    if tg_op='UPDATE' then raise exception 'archive import payload is immutable' using errcode='23514'; end if;
    select * into item from control_archive_imports where id=case when tg_op='INSERT' then new.import_id else old.import_id end;
    select epoch,phase into current_epoch,current_phase from remote_recovery_state where slot=1 for share;
    if item.id is null or current_phase is distinct from 'ready' then
        raise exception 'archive import is unavailable' using errcode='23514';
    end if;
    if tg_op='DELETE' then
        if item.retain_until>clock_timestamp() then raise exception 'archive import retention has not elapsed' using errcode='23514'; end if;
        insert into audit_log(actor_type,actor_id,action,result,metadata)
        values('system',current_user,'control.archive.import.delete','success',
            jsonb_build_object('import_id',item.id,'domain_id',item.domain_id,'export_id',item.export_id,'current_epoch',current_epoch,'db_session_user',session_user));
        return old;
    end if;
    if item.import_xid<>pg_current_xact_id() or item.target_epoch<>current_epoch
       or new.payload->>'format' is distinct from 'dsh-control-archive' or new.payload->>'version' is distinct from '1'
       or new.payload->>'domain_id' is distinct from item.domain_id::text or new.payload->>'export_id' is distinct from item.export_id::text
       or new.payload->>'operation_epoch' is distinct from item.source_epoch::text or new.payload->>'key_id' is distinct from item.key_id
       or new.payload->'batch'->>'id' is distinct from item.batch_id::text
       or new.payload->'batch'->>'database_epoch' is distinct from item.batch_epoch::text
       or (new.payload->'batch'->>'retain_until')::timestamptz is distinct from item.retain_until
       or jsonb_typeof(new.payload->'events') is distinct from 'array'
       or jsonb_array_length(new.payload->'events')<>item.event_count then
        raise exception 'archive import payload does not match identity' using errcode='23514';
    end if;
    if exists(select 1 from jsonb_array_elements(new.payload->'events') as event where jsonb_typeof(event->'acknowledgements') is distinct from 'array') then
        raise exception 'archive import acknowledgements are missing' using errcode='23514';
    end if;
    select coalesce(sum(jsonb_array_length(event->'acknowledgements')),0) into ack_count
      from jsonb_array_elements(new.payload->'events') as event;
    if ack_count<>item.acknowledgement_count then raise exception 'archive import acknowledgement count mismatch' using errcode='23514'; end if;
    return new;
end $$;
create trigger control_archive_import_payload_guard before insert or update or delete on control_archive_import_payloads
    for each row execute function control_archive_import_payload_guard();
create trigger control_archive_imports_no_truncate before truncate on control_archive_imports
    for each statement execute function control_archive_no_truncate();
create trigger control_archive_import_payloads_no_truncate before truncate on control_archive_import_payloads
    for each statement execute function control_archive_no_truncate();
revoke all on control_archive_imports,control_archive_import_payloads from public;
commit;
