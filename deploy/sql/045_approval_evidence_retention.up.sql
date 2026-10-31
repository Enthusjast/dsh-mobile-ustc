begin;
-- Extensions are append-only; captured decision bindings are never rewritten.
create table approval_evidence_retention_extensions (
    id uuid primary key,
    approval_id uuid not null references approval_decision_evidence(approval_id),
    operation_epoch uuid not null,
    source_epoch uuid not null,
    retention_years integer not null check(retention_years between 2 and 10),
    previous_retain_until timestamptz not null,
    retain_until timestamptz not null,
    recorded_at timestamptz not null,
    check(retain_until>previous_retain_until),
    unique(approval_id,retention_years)
);
create index approval_evidence_retention_source on approval_evidence_retention_extensions(approval_id,retain_until desc);
create function approval_evidence_retention_guard() returns trigger language plpgsql as $$
declare item approval_decision_evidence%rowtype; current_epoch uuid; current_phase text; permitted boolean; audit_id bigint;
begin
    if tg_op<>'INSERT' then raise exception 'evidence retention extensions are immutable' using errcode='23514'; end if;
    if current_setting('transaction_isolation')<>'read committed' then
        raise exception 'evidence retention requires a fresh read committed snapshot' using errcode='23514';
    end if;
    select epoch,phase into current_epoch,current_phase from remote_recovery_state where slot=1 for share;
    if current_phase is distinct from 'ready' or current_epoch is distinct from new.operation_epoch then
        raise exception 'evidence retention recovery is fenced' using errcode='23514';
    end if;
    -- Lock material before reading the deadline: deletion and all extensions serialize here.
    perform approval_id from approval_decision_evidence_material where approval_id=new.approval_id for update;
    if not found then raise exception 'evidence retention material is unavailable' using errcode='23514'; end if;
    select * into item from approval_decision_evidence where approval_id=new.approval_id;
    with recursive lineage(epoch) as (
        select item.database_epoch union
        select r.target_epoch from remote_recovery_runs r join lineage l on r.source_epoch=l.epoch where r.phase='ready'
    ) select exists(select 1 from lineage where epoch=current_epoch) into permitted;
    if not permitted then raise exception 'evidence retention source is fenced' using errcode='23514'; end if;
    select greatest(item.retain_until,coalesce(max(retain_until),item.retain_until)) into new.previous_retain_until
        from approval_evidence_retention_extensions where approval_id=new.approval_id;
    new.source_epoch=item.database_epoch;
    new.retain_until=((item.decided_at at time zone 'UTC')+make_interval(years=>new.retention_years)) at time zone 'UTC';
    new.recorded_at=clock_timestamp();
    if new.retention_years not between 2 and 10 or new.retain_until<=new.previous_retain_until or new.retain_until<=new.recorded_at then
        raise exception 'evidence retention must extend into the future' using errcode='23514';
    end if;
    insert into audit_log(actor_type,actor_id,action,result,metadata)
    values('system',current_user,'approval.evidence.retention.extend','success',
        jsonb_build_object('operation_id',new.id,'approval_id',new.approval_id,'source_epoch',new.source_epoch,
            'current_epoch',current_epoch,'retention_years',new.retention_years,'previous_retain_until',new.previous_retain_until,
            'retain_until',new.retain_until,'db_session_user',session_user)) returning id into audit_id;
    if audit_id is null then raise exception 'evidence retention audit is unavailable' using errcode='23514'; end if;
    return new;
end $$;
create trigger approval_evidence_retention_guard before insert or update or delete on approval_evidence_retention_extensions
    for each row execute function approval_evidence_retention_guard();
create trigger approval_evidence_retention_no_truncate before truncate on approval_evidence_retention_extensions
    for each statement execute function control_archive_no_truncate();
create function approval_evidence_retention_pin() returns trigger language plpgsql as $$
begin
    -- A snapshot taken before waiting for this row lock can otherwise miss an
    -- extension: locking does not change the material's tuple version.
    if current_setting('transaction_isolation')<>'read committed' then
        raise exception 'evidence deletion requires a fresh read committed snapshot' using errcode='23514';
    end if;
    if exists(select 1 from approval_evidence_retention_extensions where approval_id=old.approval_id and retain_until>clock_timestamp()) then
        raise exception 'extended evidence retention has not elapsed' using errcode='23514';
    end if;
    return old;
end $$;
create trigger aab_approval_evidence_retention_pin before delete on approval_decision_evidence_material
    for each row execute function approval_evidence_retention_pin();
revoke all on approval_evidence_retention_extensions from public;
commit;
