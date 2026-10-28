begin;

-- Fence new material writes across backfill and trigger installation.
lock table approval_decision_evidence_material in share row exclusive mode;

-- Keep the database-stamped audit provenance required by the verifier.
create view approval_evidence_audit_schema_guard as
    select database_epoch,producer_xid from audit_log where false;
revoke all on approval_evidence_audit_schema_guard from public;

create table approval_evidence_fingerprints (
    approval_id uuid primary key references approval_decision_evidence(approval_id),
    jws_sha256 text not null check(jws_sha256 ~ '^[0-9a-f]{64}$'),
    provenance text not null check(provenance in ('captured','backfilled')),
    recorded_at timestamptz not null default clock_timestamp()
);

-- Earlier snapshots get an anchor only when the still-present original
-- approval and material agree in all retained decision bindings. Missing or
-- inconsistent originals remain unverifiable rather than being invented.
insert into approval_evidence_fingerprints(approval_id,jws_sha256,provenance)
select e.approval_id,encode(sha256(convert_to(m.decision_jws,'UTF8')),'hex'),'backfilled'
from approval_decision_evidence e
join approval_decision_evidence_material m on m.approval_id=e.approval_id
join approvals a on a.id=e.approval_id
where a.decision_jws=m.decision_jws and a.decision_evidence_xid=e.evidence_xid and a.decision_evidence_epoch=e.database_epoch
  and row(a.runtime_id,a.runtime_epoch,a.session_id,a.execution_id,a.decided_by,a.decided_device_id,a.decision_key_version,a.decision_approval_key_jkt,
          a.decision,a.binding_sha256,a.decision_payload_sha256,a.decided_at)
      is not distinct from row(e.runtime_id,e.runtime_epoch,e.session_id,e.execution_id,e.user_id,e.device_id,e.key_version,e.approval_key_jkt,
          e.decision,e.binding_sha256,e.payload_sha256,e.decided_at);

create function approval_evidence_fingerprint_guard() returns trigger language plpgsql as $$
declare item approval_decision_evidence%rowtype; source_jws text; current_epoch uuid; current_phase text;
begin
    if tg_op<>'INSERT' then raise exception 'approval evidence fingerprint is immutable' using errcode='23514'; end if;
    select * into item from approval_decision_evidence where approval_id=new.approval_id;
    select epoch,phase into current_epoch,current_phase from remote_recovery_state where slot=1 for share;
    select decision_jws into source_jws from approvals where id=new.approval_id;
    if item.approval_id is null or source_jws is null or current_phase is distinct from 'ready'
       or item.evidence_xid<>pg_current_xact_id() or item.database_epoch<>current_epoch or new.provenance<>'captured'
       or new.jws_sha256 is distinct from encode(sha256(convert_to(source_jws,'UTF8')),'hex') then
        raise exception 'approval evidence fingerprint does not match its decision' using errcode='23514';
    end if;
    return new;
end $$;
create trigger approval_evidence_fingerprint_guard before insert or update or delete on approval_evidence_fingerprints
    for each row execute function approval_evidence_fingerprint_guard();

create function capture_approval_evidence_fingerprint() returns trigger language plpgsql as $$
begin
    insert into approval_evidence_fingerprints(approval_id,jws_sha256,provenance)
    values(new.approval_id,encode(sha256(convert_to(new.decision_jws,'UTF8')),'hex'),'captured');
    return null;
end $$;
create trigger capture_approval_evidence_fingerprint after insert on approval_decision_evidence_material
    for each row execute function capture_approval_evidence_fingerprint();
create trigger approval_evidence_fingerprints_no_truncate before truncate on approval_evidence_fingerprints
    for each statement execute function control_archive_no_truncate();
revoke all on approval_evidence_fingerprints from public;
commit;
