begin;

create table audit_cold_exports (
    id uuid primary key,
    domain_id uuid not null,
    operation_epoch uuid not null,
    batch_id uuid not null references audit_archive_batches(id),
    key_id text not null check(key_id ~ '^[A-Za-z0-9_-]{1,32}$'),
    key_fingerprint text not null check(key_fingerprint ~ '^[0-9a-f]{64}$'),
    destination_fingerprint text not null check(destination_fingerprint ~ '^[0-9a-f]{64}$'),
    salt bytea not null check(octet_length(salt)=32),
    nonce bytea not null check(octet_length(nonce)=12),
    payload_sha256 text not null check(payload_sha256 ~ '^[0-9a-f]{64}$'),
    artifact_sha256 text not null check(artifact_sha256 ~ '^[0-9a-f]{64}$'),
    artifact_size integer not null check(artifact_size between 76 and 67108940),
    entry_count integer not null check(entry_count between 0 and 128),
    prepared_at timestamptz not null,
    state text not null check(state in ('prepared','published','aborted')),
    completed_at timestamptz,
    check((state='prepared' and completed_at is null) or (state in ('published','aborted') and completed_at is not null and completed_at>=prepared_at)),
    unique(key_fingerprint,salt)
);
create index audit_cold_exports_batch on audit_cold_exports(batch_id,state);

create function audit_cold_export_guard() returns trigger language plpgsql as $$
declare current_epoch uuid; current_phase text; permitted boolean; expected_count integer; actual_count integer;
begin
    if tg_op='DELETE' then raise exception 'audit cold export is immutable' using errcode='23514'; end if;
    select epoch,phase into current_epoch,current_phase from remote_recovery_state where slot=1 for share;
    if current_phase is distinct from 'ready' then raise exception 'audit cold export recovery is not ready' using errcode='23514'; end if;
    if current_epoch<>new.operation_epoch then
        permitted=false;
        if tg_op='UPDATE' and old.state='prepared' and new.state='aborted' then
            with recursive lineage(epoch) as (
                select old.operation_epoch union
                select r.target_epoch from remote_recovery_runs r join lineage l on r.source_epoch=l.epoch where r.phase='ready'
            ) select exists(select 1 from lineage where epoch=current_epoch) into permitted;
        end if;
        if not permitted then raise exception 'audit cold export epoch is fenced' using errcode='23514'; end if;
    end if;
    if tg_op='INSERT' then
        select entry_count into expected_count from audit_archive_batches where id=new.batch_id;
        select count(*) into actual_count from audit_log_archive where batch_id=new.batch_id;
        if expected_count is null or expected_count<>new.entry_count or actual_count<>expected_count or new.state<>'prepared' then
            raise exception 'audit cold export source is incomplete' using errcode='23514';
        end if;
        return new;
    end if;
    if row(new.id,new.domain_id,new.operation_epoch,new.batch_id,new.key_id,new.key_fingerprint,new.destination_fingerprint,new.salt,new.nonce,new.payload_sha256,new.artifact_sha256,new.artifact_size,new.entry_count,new.prepared_at)
       is distinct from row(old.id,old.domain_id,old.operation_epoch,old.batch_id,old.key_id,old.key_fingerprint,old.destination_fingerprint,old.salt,old.nonce,old.payload_sha256,old.artifact_sha256,old.artifact_size,old.entry_count,old.prepared_at)
       or old.state<>'prepared' or new.state not in ('published','aborted') or new.completed_at is null then
        raise exception 'audit cold export identity or transition is invalid' using errcode='23514';
    end if;
    return new;
end $$;
create trigger audit_cold_export_guard before insert or update or delete on audit_cold_exports
    for each row execute function audit_cold_export_guard();
create trigger audit_cold_exports_no_truncate before truncate on audit_cold_exports
    for each statement execute function control_archive_no_truncate();

create function audit_cold_export_pin() returns trigger language plpgsql as $$
begin
    if exists(select 1 from audit_cold_exports where batch_id=old.batch_id and state='prepared') then
        raise exception 'audit cold export is unfinished' using errcode='23514';
    end if;
    return old;
end $$;
create trigger aaa_audit_cold_export_pin before delete on audit_log_archive
    for each row execute function audit_cold_export_pin();
revoke all on audit_cold_exports from public;
commit;
