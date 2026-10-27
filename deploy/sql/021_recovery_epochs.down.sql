begin;
do $$ begin
    if exists(select 1 from remote_recovery_runs) or exists(select 1 from remote_recovery_state where epoch<>'00000000-0000-4000-8000-000000000000'::uuid) then
        raise exception 'recovery epoch migration cannot be rolled back after recovery; use a forward migration' using errcode='23514';
    end if;
end $$;
create or replace function control_outbox_identity() returns trigger language plpgsql as $$
begin
    if tg_op='INSERT' then new.producer_xid=pg_current_xact_id();return new;end if;
    if row(new.id,new.org_id,new.topic,new.payload,new.created_at,new.producer_xid)
        is distinct from row(old.id,old.org_id,old.topic,old.payload,old.created_at,old.producer_xid) then
        raise exception 'control event identity and payload are immutable' using errcode='23514';
    end if;
    return new;
end $$;
drop index control_outbox_epoch_producer;
create index control_outbox_producer on control_outbox(producer_xid,created_at,id);
alter table control_outbox drop column database_epoch;
alter table control_consumers drop column database_epoch;
drop function remote_database_epoch();
drop table remote_recovery_memberships;
drop table remote_recovery_state;
drop table remote_recovery_runs;
commit;
