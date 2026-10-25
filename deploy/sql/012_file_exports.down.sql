begin;

-- Preserve object tracking and quota reservations for the common GC path.
update files set state='expired' where id in (select file_id from file_exports);
update file_scan_attempts set state='abandoned',finished_at=clock_timestamp()
    where state='active' and file_id in (select file_id from file_exports);
update file_objects set cleanup_after=least(cleanup_after,clock_timestamp()+interval '15 minutes')
    where file_id in (select file_id from file_exports);
drop table file_exports;

commit;
