begin;
do $$ begin
    if exists(select 1 from approval_evidence_exports) then
        raise exception 'approval evidence export history prevents destructive rollback';
    end if;
end $$;
drop trigger aaa_approval_evidence_export_pin on approval_decision_evidence_material;
drop function approval_evidence_export_pin();
drop table approval_evidence_exports;
drop function approval_evidence_export_guard();
commit;
