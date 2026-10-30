begin;
do $$ begin
    if exists(select 1 from command_rate_counters) then
        raise exception '038_command_rates rollback requires a controlled offline policy migration; retained budgets are not erased automatically';
    end if;
end $$;
drop table command_rate_counters;
drop table command_rate_policy;
commit;
