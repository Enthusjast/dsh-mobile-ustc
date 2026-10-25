begin;

-- One upload intent belongs to one message intent. No message body or native
-- receipt is stored here; the command's digest binds its ordered content.
create table file_message_refs (
    file_id uuid primary key references file_transfers(file_id),
    device_id uuid not null,
    request_id uuid not null,
    handoff_id uuid not null references file_handoffs(id),
    created_at timestamptz not null default clock_timestamp(),
    foreign key (device_id,request_id) references commands(device_id,request_id)
);
create index file_message_command on file_message_refs(device_id,request_id);

commit;
