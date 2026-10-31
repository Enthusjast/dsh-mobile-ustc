alter table sessions add column directory_metadata jsonb;
alter table sessions add constraint sessions_directory_metadata_shape check (
    directory_metadata is null or (
        jsonb_typeof(directory_metadata) = 'object'
        and directory_metadata->'v' = '1'::jsonb
        and octet_length(directory_metadata::text) <= 4096
    )
);

-- A replacement connection cannot inherit a previous producer's display claims.
-- Offline disconnection itself leaves the last registered directory available.
create function clear_replaced_runtime_directory_metadata() returns trigger language plpgsql as $$
begin
    if new.connection_id is not null and new.connection_id is distinct from old.connection_id then
        update sessions set directory_metadata = null where runtime_id = new.id;
    end if;
    return new;
end;
$$;
create trigger clear_replaced_runtime_directory_metadata
    after update of connection_id on runtimes
    for each row execute function clear_replaced_runtime_directory_metadata();
