begin;
do $$ begin
    if exists(select 1 from approval_decision_evidence) then
        raise exception 'approval decision evidence prevents destructive rollback';
    end if;
end $$;
drop view approval_decision_evidence_schema_guard;
drop trigger capture_approval_decision_evidence on approvals;
drop function capture_approval_decision_evidence();
drop table approval_decision_evidence_material;
drop table approval_decision_evidence;
drop function approval_decision_evidence_material_guard();
drop function approval_decision_evidence_guard();
drop trigger approval_decision_evidence_owner on approvals;
drop function approval_decision_evidence_owner();
alter table approvals drop column decision_evidence_xid;
alter table approvals drop column decision_evidence_epoch;
commit;
