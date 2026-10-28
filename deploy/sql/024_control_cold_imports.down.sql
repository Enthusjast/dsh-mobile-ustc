begin;
do $$ begin
    if exists(select 1 from control_archive_imports) then
        raise exception 'archive import history prevents destructive rollback';
    end if;
end $$;
drop table control_archive_import_payloads;
drop table control_archive_imports;
drop function control_archive_import_payload_guard();
drop function control_archive_import_complete_guard();
drop function control_archive_import_guard();
commit;
