begin;

create table file_exports (
    file_id uuid primary key references file_transfers(file_id),
    source_id uuid not null,
    installation_id uuid not null references installations(id),
    installation_key_version bigint not null check (installation_key_version > 0),
    runtime_epoch uuid not null,
    connection_id uuid not null,
    credential_expires_at timestamptz not null,
    source_expires_at timestamptz not null,
    uploaded_at timestamptz
);

-- Direction is authority, not a UI hint. All export data needs provenance;
-- old from_host rows cannot be promoted through the new transfer ledger.
update files set state='expired' where direction='from_host';

commit;
