begin;
do $$ begin
    if exists(select 1 from command_rate_policy_changes) then
        raise exception '039_command_rate_policy_changes cannot erase retained policy change evidence';
    end if;
end $$;
drop table command_rate_policy_changes;
drop function command_rate_change_immutable();
commit;
