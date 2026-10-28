begin;
do $$ begin
    if exists(select 1 from audit_archive_batches) or exists(select 1 from audit_log where database_epoch is not null)
       or exists(select 1 from remote_recovery_runs) then
        raise exception 'audit provenance or archive history prevents destructive rollback';
    end if;
end $$;
drop trigger audit_log_no_truncate on audit_log;
drop trigger audit_log_immutable on audit_log;
drop function audit_log_immutable();
drop table audit_log_archive;
drop table audit_archive_batches;
drop function audit_archive_complete_guard();
drop function audit_archive_entry_guard();
drop function audit_archive_batch_guard();
drop trigger audit_log_stamp on audit_log;
drop function audit_log_stamp();
drop index audit_log_archive_candidates;
alter table audit_log drop column producer_xid;
alter table audit_log drop column database_epoch;
commit;
