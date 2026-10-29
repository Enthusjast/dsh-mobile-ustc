begin;
do $$ begin
    if exists(select 1 from cold_history_imports) then
        raise exception 'cold history import identities prevent destructive rollback';
    end if;
end $$;
drop view cold_history_import_schema_guard;
drop table cold_history_import_payloads;
drop table cold_history_imports;
drop function cold_history_import_payload_guard();
drop function cold_history_import_complete_guard();
drop function cold_history_import_guard();
commit;
