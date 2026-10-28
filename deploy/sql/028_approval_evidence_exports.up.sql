begin;

create table approval_evidence_exports (
    id uuid primary key,
    domain_id uuid not null,
    operation_epoch uuid not null,
    approval_id uuid not null references approval_evidence_fingerprints(approval_id),
    key_id text not null check(key_id ~ '^[A-Za-z0-9_-]{1,32}$'),
    key_fingerprint text not null check(key_fingerprint ~ '^[0-9a-f]{64}$'),
    destination_fingerprint text not null check(destination_fingerprint ~ '^[0-9a-f]{64}$'),
    salt bytea not null check(octet_length(salt)=32),
    nonce bytea not null check(octet_length(nonce)=12),
    payload_sha256 text not null check(payload_sha256 ~ '^[0-9a-f]{64}$'),
    artifact_sha256 text not null check(artifact_sha256 ~ '^[0-9a-f]{64}$'),
    artifact_size integer not null check(artifact_size between 76 and 8388684),
    prepared_at timestamptz not null,
    state text not null check(state in ('prepared','published','aborted')),
    completed_at timestamptz,
    check((state='prepared' and completed_at is null) or (state in ('published','aborted') and completed_at is not null and completed_at>=prepared_at)),
    unique(key_fingerprint,salt)
);
create index approval_evidence_exports_source on approval_evidence_exports(approval_id,state);

create function approval_evidence_export_guard() returns trigger language plpgsql as $$
declare current_epoch uuid; current_phase text; permitted boolean;
begin
    if tg_op='DELETE' then raise exception 'approval evidence export is immutable' using errcode='23514'; end if;
    select epoch,phase into current_epoch,current_phase from remote_recovery_state where slot=1 for share;
    if current_phase is distinct from 'ready' then raise exception 'approval evidence export recovery is not ready' using errcode='23514'; end if;
    if current_epoch<>new.operation_epoch then
        permitted=false;
        if tg_op='UPDATE' and old.state='prepared' and new.state='aborted' then
            with recursive lineage(epoch) as (
                select old.operation_epoch union
                select r.target_epoch from remote_recovery_runs r join lineage l on r.source_epoch=l.epoch where r.phase='ready'
            ) select exists(select 1 from lineage where epoch=current_epoch) into permitted;
        end if;
        if not permitted then raise exception 'approval evidence export epoch is fenced' using errcode='23514'; end if;
    end if;
    if tg_op='INSERT' then
        if new.state<>'prepared' or not exists(select 1 from approval_decision_evidence_material where approval_id=new.approval_id) then
            raise exception 'approval evidence export source is unavailable' using errcode='23514';
        end if;
        return new;
    end if;
    if row(new.id,new.domain_id,new.operation_epoch,new.approval_id,new.key_id,new.key_fingerprint,new.destination_fingerprint,new.salt,new.nonce,new.payload_sha256,new.artifact_sha256,new.artifact_size,new.prepared_at)
       is distinct from row(old.id,old.domain_id,old.operation_epoch,old.approval_id,old.key_id,old.key_fingerprint,old.destination_fingerprint,old.salt,old.nonce,old.payload_sha256,old.artifact_sha256,old.artifact_size,old.prepared_at)
       or old.state<>'prepared' or new.state not in ('published','aborted') or new.completed_at is null then
        raise exception 'approval evidence export identity or transition is invalid' using errcode='23514';
    end if;
    return new;
end $$;
create trigger approval_evidence_export_guard before insert or update or delete on approval_evidence_exports
    for each row execute function approval_evidence_export_guard();
create trigger approval_evidence_exports_no_truncate before truncate on approval_evidence_exports
    for each statement execute function control_archive_no_truncate();

-- An unfinished operation pins material even after the normal retention time.
create function approval_evidence_export_pin() returns trigger language plpgsql as $$
begin
    if exists(select 1 from approval_evidence_exports where approval_id=old.approval_id and state='prepared') then
        raise exception 'approval evidence export is unfinished' using errcode='23514';
    end if;
    return old;
end $$;
create trigger aaa_approval_evidence_export_pin before delete on approval_decision_evidence_material
    for each row execute function approval_evidence_export_pin();
revoke all on approval_evidence_exports from public;
commit;
