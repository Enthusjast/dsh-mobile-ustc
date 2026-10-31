begin;
do $$ begin
    if exists(select 1 from command_archive_batches) or exists(select 1 from command_archive)
       or exists(select 1 from command_keys k where not exists(select 1 from commands c where c.device_id=k.device_id and c.request_id=k.request_id)) then
        raise exception 'command archive identities prevent destructive rollback';
    end if;
end $$;
drop trigger file_message_command_owner on file_message_refs;
drop function file_message_command_owner();
alter table file_message_refs drop constraint file_message_refs_key_fk;
alter table file_message_refs add constraint file_message_refs_device_id_request_id_fkey foreign key(device_id,request_id) references commands(device_id,request_id);
drop view command_records;
drop trigger command_archive_delete_guard on commands;
drop function command_archive_delete_guard();
drop trigger commands_no_truncate on commands;
drop trigger command_key_owner on commands;
drop function command_key_owner();
alter table commands drop constraint commands_key_fk;
drop table command_archive;
drop table command_archive_batches;
drop function command_archive_complete_guard();
drop function command_archive_entry_guard();
drop function command_archive_batch_guard();
drop table command_keys;
drop function command_keys_immutable();
drop index commands_archive_candidates;
commit;
