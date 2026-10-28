begin;
do $$ begin
    if exists(select 1 from control_archive_batches) or exists(select 1 from control_outbox_archive) or exists(select 1 from control_event_ack_archive) or exists(select 1 from remote_recovery_runs) then
        raise exception 'control archive history prevents destructive rollback';
    end if;
end $$;
drop trigger control_outbox_no_truncate on control_outbox;
drop trigger control_ack_no_truncate on control_event_acks;
drop trigger control_consumer_no_truncate on control_consumers;
drop trigger control_outbox_retention_guard on control_outbox;
drop function control_outbox_retention_guard();
drop trigger control_hot_ack_retention_guard on control_event_acks;
drop function control_hot_ack_retention_guard();
drop trigger control_consumer_archive_bootstrap on control_consumers;
drop function control_consumer_archive_bootstrap();
drop trigger control_consumer_archive_delete_guard on control_consumers;
drop function control_consumer_archive_delete_guard();
drop table control_event_ack_archive;
drop function control_archive_ack_immutable();
drop table control_outbox_archive;
drop table control_archive_batches;
drop function control_archive_immutable();
drop function control_archive_no_truncate();
drop index control_outbox_retention;
commit;
