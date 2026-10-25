begin;

update files set state='expired' where id in (select file_id from file_exports);
update file_scan_attempts set state='abandoned',finished_at=clock_timestamp()
    where state='active' and file_id in (select file_id from file_exports);
alter table file_exports drop constraint export_origin_workspace;
alter table file_exports drop column workspace_id;
alter table file_exports drop column origin;

commit;
