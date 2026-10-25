begin;

-- Dropping the ownership ledger must not make consumed uploads reusable.
update files f set state='expired' from file_message_refs r where r.file_id=f.id;
update file_transfers f set error_code='expired' from file_message_refs r where r.file_id=f.file_id;
update file_handoffs h set state='invalidated',staged_name=null,ended_at=clock_timestamp()
where h.file_id in (select file_id from file_message_refs) and h.state in ('offered','downloading','staged');
drop table file_message_refs;

commit;
