begin;
do $$ begin
    if exists(select 1 from approval_evidence_fingerprints) then
        raise exception 'approval evidence fingerprints prevent destructive rollback';
    end if;
end $$;
drop view approval_evidence_audit_schema_guard;
drop trigger capture_approval_evidence_fingerprint on approval_decision_evidence_material;
drop function capture_approval_evidence_fingerprint();
drop table approval_evidence_fingerprints;
drop function approval_evidence_fingerprint_guard();
commit;
