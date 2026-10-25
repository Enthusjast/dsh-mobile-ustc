begin;

create table file_handoffs (
    id uuid primary key,
    file_id uuid not null references file_transfers(file_id),
    installation_id uuid not null references installations(id),
    installation_key_version bigint not null check (installation_key_version>0),
    runtime_id uuid not null references runtimes(id),
    runtime_epoch uuid not null,
    connection_id uuid not null,
    scanner_policy_sha256 text not null check (scanner_policy_sha256 ~ '^[0-9a-f]{64}$'),
    token_sha256 bytea not null unique check (octet_length(token_sha256)=32),
    state text not null check (state in ('offered','downloading','staged','failed','invalidated','expired')),
    lease_until timestamptz not null,
    expires_at timestamptz not null,
    credential_expires_at timestamptz not null,
    read_started_at timestamptz,
    staged_name text,
    created_at timestamptz not null default clock_timestamp(),
    ended_at timestamptz,
    check (lease_until<=expires_at and expires_at<=credential_expires_at),
    check ((state='staged')=(staged_name is not null))
);
create unique index file_handoff_one_active on file_handoffs(file_id) where state in ('offered','downloading','staged');
create index file_handoff_connection on file_handoffs(runtime_id,connection_id) where state in ('offered','downloading','staged');

commit;
