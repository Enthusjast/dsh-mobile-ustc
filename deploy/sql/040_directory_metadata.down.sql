drop trigger clear_replaced_runtime_directory_metadata on runtimes;
drop function clear_replaced_runtime_directory_metadata();
alter table sessions drop constraint sessions_directory_metadata_shape;
alter table sessions drop column directory_metadata;
