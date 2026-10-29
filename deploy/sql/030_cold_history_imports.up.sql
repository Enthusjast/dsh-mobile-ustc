begin;

-- Keep the export schemas present while this importer is installed.
create view cold_history_import_schema_guard as
    select 'audit'::text as kind,id from audit_cold_exports where false
    union all select 'approval'::text as kind,id from approval_evidence_exports where false;
revoke all on cold_history_import_schema_guard from public;

create table cold_history_imports (
    id uuid primary key,
    kind text not null check(kind in ('audit','approval')),
    domain_id uuid not null,
    export_id uuid not null,
    object_id uuid not null,
    source_epoch uuid not null,
    operation_epoch uuid not null,
    target_epoch uuid not null,
    key_id text not null check(key_id ~ '^[A-Za-z0-9_-]{1,32}$'),
    key_fingerprint text not null check(key_fingerprint ~ '^[0-9a-f]{64}$'),
    artifact_sha256 text not null check(artifact_sha256 ~ '^[0-9a-f]{64}$'),
    artifact_size integer not null check(artifact_size between 76 and 67108940),
    payload_sha256 text not null check(payload_sha256 ~ '^[0-9a-f]{64}$'),
    entry_count integer not null check(entry_count between 0 and 128),
    retain_until timestamptz not null,
    imported_at timestamptz not null,
    import_xid xid8 not null default pg_current_xact_id(),
    check(kind<>'approval' or entry_count=1),
    unique(kind,domain_id,export_id)
);
create table cold_history_import_payloads (
    import_id uuid primary key references cold_history_imports(id),
    payload jsonb not null check(jsonb_typeof(payload)='object' and octet_length(payload::text)<=134217728)
);

create function cold_history_import_guard() returns trigger language plpgsql as $$
declare current_epoch uuid; current_phase text;
begin
    if tg_op<>'INSERT' then raise exception 'cold history import identity is immutable' using errcode='23514'; end if;
    select epoch,phase into current_epoch,current_phase from remote_recovery_state where slot=1 for share;
    if current_phase is distinct from 'ready' or current_epoch is distinct from new.target_epoch then
        raise exception 'cold history import epoch is not ready' using errcode='23514';
    end if;
    new.import_xid=pg_current_xact_id();
    return new;
end $$;
create trigger cold_history_import_guard before insert or update or delete on cold_history_imports
    for each row execute function cold_history_import_guard();

create function cold_history_import_complete_guard() returns trigger language plpgsql as $$
begin
    if not exists(select 1 from cold_history_import_payloads where import_id=new.id) then
        raise exception 'cold history import payload is missing' using errcode='23514';
    end if;
    return null;
end $$;
create constraint trigger cold_history_import_complete_guard after insert on cold_history_imports
    deferrable initially deferred for each row execute function cold_history_import_complete_guard();

create function cold_history_import_payload_guard() returns trigger language plpgsql as $$
declare item cold_history_imports%rowtype; current_epoch uuid; current_phase text; expected_format text; object_id text; source_epoch text; retained timestamptz; count_entries integer;
begin
    if tg_op='UPDATE' then raise exception 'cold history import payload is immutable' using errcode='23514'; end if;
    select * into item from cold_history_imports where id=case when tg_op='INSERT' then new.import_id else old.import_id end;
    select epoch,phase into current_epoch,current_phase from remote_recovery_state where slot=1 for share;
    if item.id is null or current_phase is distinct from 'ready' then raise exception 'cold history import is unavailable' using errcode='23514'; end if;
    if tg_op='DELETE' then
        if item.retain_until>clock_timestamp() then raise exception 'cold history import retention has not elapsed' using errcode='23514'; end if;
        insert into audit_log(actor_type,actor_id,action,result,metadata)
        values('system',current_user,'cold.history.import.delete','success',
            jsonb_build_object('import_id',item.id,'kind',item.kind,'domain_id',item.domain_id,'export_id',item.export_id,'current_epoch',current_epoch,'db_session_user',session_user));
        return old;
    end if;
    if item.import_xid<>pg_current_xact_id() or item.target_epoch<>current_epoch then
        raise exception 'cold history payload must be created with its import' using errcode='23514';
    end if;
    if item.kind='audit' then
        expected_format='dsh-audit-archive'; object_id=new.payload->'batch'->>'id';
        source_epoch=new.payload->'batch'->>'database_epoch'; retained=(new.payload->'batch'->>'retain_until')::timestamptz;
        if jsonb_typeof(new.payload->'entries') is distinct from 'array' then raise exception 'audit entries missing' using errcode='23514'; end if;
        count_entries=jsonb_array_length(new.payload->'entries');
    else
        expected_format='dsh-approval-evidence'; object_id=new.payload->'proof'->>'approval_id';
        source_epoch=new.payload->'proof'->>'source_epoch'; retained=(new.payload->'proof'->>'retain_until')::timestamptz;
        count_entries=1;
    end if;
    if new.payload->>'format' is distinct from expected_format or new.payload->>'version' is distinct from '1'
       or new.payload->>'domain_id' is distinct from item.domain_id::text or new.payload->>'export_id' is distinct from item.export_id::text
       or new.payload->>'operation_epoch' is distinct from item.operation_epoch::text or new.payload->>'key_id' is distinct from item.key_id
       or object_id is distinct from item.object_id::text or source_epoch is distinct from item.source_epoch::text
       or retained is distinct from item.retain_until or count_entries<>item.entry_count then
        raise exception 'cold history import payload does not match identity' using errcode='23514';
    end if;
    return new;
end $$;
create trigger cold_history_import_payload_guard before insert or update or delete on cold_history_import_payloads
    for each row execute function cold_history_import_payload_guard();
create trigger cold_history_imports_no_truncate before truncate on cold_history_imports
    for each statement execute function control_archive_no_truncate();
create trigger cold_history_import_payloads_no_truncate before truncate on cold_history_import_payloads
    for each statement execute function control_archive_no_truncate();
revoke all on cold_history_imports,cold_history_import_payloads from public;
commit;
