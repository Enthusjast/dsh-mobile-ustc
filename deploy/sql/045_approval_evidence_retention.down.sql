begin;
do $$ begin
    if exists(select 1 from approval_evidence_retention_extensions) then
        raise exception 'evidence retention extensions prevent destructive rollback';
    end if;
end $$;
drop trigger aab_approval_evidence_retention_pin on approval_decision_evidence_material;
drop function approval_evidence_retention_pin();
drop table approval_evidence_retention_extensions;
drop function approval_evidence_retention_guard();
commit;
