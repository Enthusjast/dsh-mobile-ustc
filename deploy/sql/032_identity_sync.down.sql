begin;
do $$ begin
    if exists(select 1 from identity_sync_runs) then
        raise exception '032_identity_sync cannot roll back after an identity synchronization';
    end if;
end $$;
drop table identity_sync_sources;
drop table identity_sync_runs;
commit;
