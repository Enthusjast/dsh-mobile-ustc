drop table control_event_acks;
drop table control_consumers;
drop trigger control_outbox_identity on control_outbox;
drop function control_outbox_identity();
drop index control_outbox_producer;
alter table control_outbox drop column producer_xid;
