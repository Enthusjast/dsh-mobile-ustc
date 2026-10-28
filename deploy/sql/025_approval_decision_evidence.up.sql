begin;

-- Legacy decisions have no trusted at-decision key snapshot and remain NULL.
alter table approvals add column decision_evidence_xid xid8;
alter table approvals add column decision_evidence_epoch uuid;

-- An older migration must not drop fields still required by evidence capture.
-- This view contains no rows; its schema dependency enforces rollback order.
create view approval_decision_evidence_schema_guard as
    select metadata_version,decision,decision_payload_sha256,decision_key_version,
           decision_approval_key_jkt,decision_proof_key_jkt,decision_grant_version,
           decision_expires_at,authenticated_at,access_token_expires_at,workspace_id,
           connection_id,nonce_sha256,assurance_profile,max_auth_age_seconds,request_created_at,runtime_id,
           host_state,host_updated_at,execution_outcome
    from approvals where false;
revoke all on approval_decision_evidence_schema_guard from public;

create table approval_decision_evidence (
    approval_id uuid primary key,
    database_epoch uuid not null,
    runtime_id uuid not null,
    runtime_epoch uuid not null,
    session_id uuid not null,
    execution_id uuid not null,
    user_id uuid not null,
    device_id uuid not null,
    key_version bigint not null check(key_version between 1 and 9007199254740991),
    approval_key_jkt text not null check(length(approval_key_jkt)=43),
    decision text not null check(decision in ('allow_once','reject')),
    binding_sha256 text not null check(binding_sha256 ~ '^[0-9a-f]{64}$'),
    payload_sha256 text not null check(payload_sha256 ~ '^[0-9a-f]{64}$'),
    decided_at timestamptz not null,
    retain_until timestamptz not null,
    evidence_xid xid8 not null default pg_current_xact_id(),
    check(retain_until>=((decided_at at time zone 'UTC')+interval '1 year') at time zone 'UTC')
);
create table approval_decision_evidence_material (
    approval_id uuid primary key references approval_decision_evidence(approval_id),
    decision_jws text not null check(length(decision_jws) between 1 and 16384),
    public_jwk jsonb not null check(jsonb_typeof(public_jwk)='object' and octet_length(public_jwk::text)<=8192
        and public_jwk->>'kty' is not distinct from 'EC' and public_jwk->>'crv' is not distinct from 'P-256'
        and jsonb_typeof(public_jwk->'x') is not distinct from 'string' and jsonb_typeof(public_jwk->'y') is not distinct from 'string'
        and (public_jwk - array['kty','crv','x','y'])='{}'::jsonb)
);

-- Immutable decision bindings do not constrain later host/result state changes.
create function approval_decision_evidence_owner() returns trigger language plpgsql as $$
declare current_epoch uuid; current_phase text;
begin
    if tg_op='INSERT' then
        if new.decision_evidence_xid is not null or new.decision_evidence_epoch is not null
           or (new.metadata_version=1 and new.decision is not null) then
            raise exception 'decision must be captured on its transition' using errcode='23514';
        end if;
        return new;
    end if;
    if old.metadata_version=1 and new.metadata_version is distinct from old.metadata_version then
        raise exception 'approval metadata version is immutable' using errcode='23514';
    end if;
    if (old.decision_evidence_xid is not null or (old.metadata_version=1 and old.decision is not null)) and
       row(new.id,new.metadata_version,new.runtime_id,new.runtime_epoch,new.session_id,new.execution_id,new.binding_sha256,new.policy_version,
           new.workspace_id,new.connection_id,new.nonce_sha256,new.assurance_profile,new.max_auth_age_seconds,new.request_created_at,new.expires_at,
           new.decision,new.decided_by,new.decided_device_id,new.decision_jws,new.decision_payload_sha256,new.decision_key_version,
           new.decision_approval_key_jkt,new.decision_proof_key_jkt,new.decision_grant_version,new.decision_expires_at,
           new.authenticated_at,new.access_token_expires_at,new.decided_at,new.decision_evidence_xid,new.decision_evidence_epoch)
       is distinct from
       row(old.id,old.metadata_version,old.runtime_id,old.runtime_epoch,old.session_id,old.execution_id,old.binding_sha256,old.policy_version,
           old.workspace_id,old.connection_id,old.nonce_sha256,old.assurance_profile,old.max_auth_age_seconds,old.request_created_at,old.expires_at,
           old.decision,old.decided_by,old.decided_device_id,old.decision_jws,old.decision_payload_sha256,old.decision_key_version,
           old.decision_approval_key_jkt,old.decision_proof_key_jkt,old.decision_grant_version,old.decision_expires_at,
           old.authenticated_at,old.access_token_expires_at,old.decided_at,old.decision_evidence_xid,old.decision_evidence_epoch) then
        raise exception 'captured approval decision is immutable' using errcode='23514';
    end if;
    if old.decision_evidence_xid is null and (new.decision_evidence_xid is not null or new.decision_evidence_epoch is not null) then
        raise exception 'decision evidence ownership is automatic' using errcode='23514';
    end if;
    if old.decision is null and new.decision is not null and new.metadata_version=1 then
        select epoch,phase into current_epoch,current_phase from remote_recovery_state where slot=1 for share;
        if current_phase is distinct from 'ready' then raise exception 'decision recovery is not ready' using errcode='23514'; end if;
        new.decision_evidence_xid=pg_current_xact_id();
        new.decision_evidence_epoch=current_epoch;
    end if;
    return new;
end $$;
create trigger approval_decision_evidence_owner before insert or update on approvals
    for each row execute function approval_decision_evidence_owner();

create function approval_decision_evidence_guard() returns trigger language plpgsql as $$
declare item approvals%rowtype; current_epoch uuid; current_phase text;
begin
    if tg_op<>'INSERT' then raise exception 'decision evidence identity is immutable' using errcode='23514'; end if;
    select * into item from approvals where id=new.approval_id;
    select epoch,phase into current_epoch,current_phase from remote_recovery_state where slot=1 for share;
    if item.id is null or current_phase is distinct from 'ready' or item.decision_evidence_xid is distinct from pg_current_xact_id()
       or item.decision_evidence_epoch is distinct from current_epoch
       or row(new.database_epoch,new.runtime_id,new.runtime_epoch,new.session_id,new.execution_id,new.user_id,new.device_id,new.key_version,new.approval_key_jkt,new.decision,new.binding_sha256,new.payload_sha256,new.decided_at)
          is distinct from row(item.decision_evidence_epoch,item.runtime_id,item.runtime_epoch,item.session_id,item.execution_id,item.decided_by,item.decided_device_id,item.decision_key_version,item.decision_approval_key_jkt,item.decision,item.binding_sha256,item.decision_payload_sha256,item.decided_at) then
        raise exception 'decision evidence does not match its transition' using errcode='23514';
    end if;
    new.evidence_xid=pg_current_xact_id();
    return new;
end $$;
create trigger approval_decision_evidence_guard before insert or update or delete on approval_decision_evidence
    for each row execute function approval_decision_evidence_guard();

create function approval_decision_evidence_material_guard() returns trigger language plpgsql as $$
declare item approval_decision_evidence%rowtype; current_epoch uuid; current_phase text; actual_jws text; actual_jwk jsonb;
begin
    if tg_op='UPDATE' then raise exception 'decision evidence material is immutable' using errcode='23514'; end if;
    select * into item from approval_decision_evidence where approval_id=case when tg_op='INSERT' then new.approval_id else old.approval_id end;
    select epoch,phase into current_epoch,current_phase from remote_recovery_state where slot=1 for share;
    if item.approval_id is null or current_phase is distinct from 'ready' then raise exception 'decision evidence is unavailable' using errcode='23514'; end if;
    if tg_op='DELETE' then
        if item.retain_until>clock_timestamp() then raise exception 'decision evidence retention has not elapsed' using errcode='23514'; end if;
        insert into audit_log(actor_type,actor_id,action,result,metadata)
        values('system',current_user,'approval.evidence.material.delete','success',
            jsonb_build_object('approval_id',item.approval_id,'database_epoch',item.database_epoch,'current_epoch',current_epoch,'db_session_user',session_user));
        return old;
    end if;
    if item.evidence_xid<>pg_current_xact_id() or item.database_epoch<>current_epoch then
        raise exception 'decision evidence is from another transition' using errcode='23514';
    end if;
    select a.decision_jws,jsonb_build_object('kty',d.approval_public_jwk->'kty','crv',d.approval_public_jwk->'crv',
        'x',d.approval_public_jwk->'x','y',d.approval_public_jwk->'y') into actual_jws,actual_jwk
      from approvals a join devices d on d.id=a.decided_device_id
      where a.id=item.approval_id and d.user_id=item.user_id and d.key_version=item.key_version and d.approval_key_thumbprint=item.approval_key_jkt for share of d;
    if new.decision_jws is distinct from actual_jws or new.public_jwk is distinct from actual_jwk then
        raise exception 'decision evidence key or signature does not match' using errcode='23514';
    end if;
    return new;
end $$;
create trigger approval_decision_evidence_material_guard before insert or update or delete on approval_decision_evidence_material
    for each row execute function approval_decision_evidence_material_guard();

create function capture_approval_decision_evidence() returns trigger language plpgsql as $$
declare public_key jsonb;
begin
    if old.decision is not null or new.decision is null or new.metadata_version<>1 then return null; end if;
    select jsonb_build_object('kty',approval_public_jwk->'kty','crv',approval_public_jwk->'crv',
        'x',approval_public_jwk->'x','y',approval_public_jwk->'y') into public_key from devices where id=new.decided_device_id and user_id=new.decided_by
      and key_version=new.decision_key_version and approval_key_thumbprint=new.decision_approval_key_jkt for share;
    if public_key is null then raise exception 'decision evidence key is unavailable' using errcode='23514'; end if;
    insert into approval_decision_evidence(approval_id,database_epoch,runtime_id,runtime_epoch,session_id,execution_id,user_id,device_id,key_version,approval_key_jkt,decision,binding_sha256,payload_sha256,decided_at,retain_until)
    values(new.id,new.decision_evidence_epoch,new.runtime_id,new.runtime_epoch,new.session_id,new.execution_id,new.decided_by,new.decided_device_id,new.decision_key_version,new.decision_approval_key_jkt,new.decision,new.binding_sha256,new.decision_payload_sha256,new.decided_at,
        ((new.decided_at at time zone 'UTC')+interval '1 year') at time zone 'UTC');
    insert into approval_decision_evidence_material(approval_id,decision_jws,public_jwk) values(new.id,new.decision_jws,public_key);
    return null;
end $$;
create trigger capture_approval_decision_evidence after update on approvals
    for each row execute function capture_approval_decision_evidence();
create trigger approval_decision_evidence_no_truncate before truncate on approval_decision_evidence
    for each statement execute function control_archive_no_truncate();
create trigger approval_decision_evidence_material_no_truncate before truncate on approval_decision_evidence_material
    for each statement execute function control_archive_no_truncate();
revoke all on approval_decision_evidence,approval_decision_evidence_material from public;
commit;
