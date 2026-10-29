begin;
do $$ begin
    if exists(select 1 from audit_cold_exports) then
        raise exception 'audit cold export history prevents destructive rollback';
    end if;
end $$;
drop trigger aaa_audit_cold_export_pin on audit_log_archive;
drop function audit_cold_export_pin();
drop table audit_cold_exports;
drop function audit_cold_export_guard();
commit;
