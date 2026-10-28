begin;
do $$ begin
    if exists(select 1 from control_archive_exports) or exists(select 1 from control_archive_batches) or exists(select 1 from remote_recovery_runs) then
        raise exception 'archive export history prevents destructive rollback';
    end if;
end $$;
drop table control_archive_exports;
drop function control_archive_export_guard();
drop trigger control_archive_ack_insert_guard on control_event_ack_archive;
drop function control_archive_ack_insert_guard();
drop trigger control_archive_batch_event_guard on control_archive_batches;
drop trigger control_archive_batch_event_guard on control_outbox_archive;
drop function control_archive_batch_event_guard();
drop trigger control_archive_batch_write_owner on control_archive_batches;
drop trigger control_archive_write_owner on control_outbox_archive;
drop function control_archive_write_owner();
alter table control_archive_batches drop column archive_xid;
alter table control_archive_batches drop column archive_write_epoch;
alter table control_outbox_archive drop column archive_xid;
alter table control_outbox_archive drop column archive_write_epoch;
create or replace function control_archive_immutable() returns trigger language plpgsql as $$
declare current_phase text;
begin
    if tg_op='UPDATE' or tg_table_name='control_archive_batches' then
        raise exception 'control archive history is immutable' using errcode='23514';
    end if;
    if old.retain_until>clock_timestamp() then
        raise exception 'control archive retention has not elapsed' using errcode='23514';
    end if;
    select phase into current_phase from remote_recovery_state where slot=1 for share;
    if current_phase is distinct from 'ready' then
        raise exception 'control archive recovery is not ready' using errcode='23514';
    end if;
    insert into audit_log(actor_type,actor_id,action,result,metadata)
    values('system',current_user,'control.archive.delete','success',
        jsonb_build_object('event_id',old.event_id,'batch_id',old.batch_id,'database_epoch',old.database_epoch,'db_session_user',session_user));
    return old;
end $$;
commit;
