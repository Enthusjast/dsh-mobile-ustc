begin;
do $$ begin
    if exists(select 1 from realtime_device_connections) then
        raise exception '041_connection_limits rollback requires all device connection occupancy released';
    end if;
end $$;
drop table realtime_device_connections;
drop table realtime_connection_policy;
commit;
