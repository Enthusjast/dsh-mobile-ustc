begin;
do $$ begin
    if exists(select 1 from realtime_connection_policy_changes) then
        raise exception '043_realtime_connection_policy_changes cannot erase retained policy change evidence';
    end if;
end $$;
drop table realtime_connection_policy_changes;
drop function connection_policy_change_immutable();
commit;
