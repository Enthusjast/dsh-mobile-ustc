begin;

update files set state='expired' where id in (select file_id from file_transfers);
drop table if exists file_objects;
drop index if exists files_expiry;
drop table if exists file_scan_attempts;
drop table if exists file_quota_usage;
drop table if exists file_transfers;
-- Expired legacy records are not made clean by rolling back schema.

commit;
