begin;
create table identity_sync_runs (
    id uuid primary key,
    database_epoch uuid not null,
    issuer text not null,
    expected_revision bigint not null check(expected_revision>=0),
    revision bigint not null check(revision=expected_revision+1 and revision<=9007199254740991),
    snapshot_sha256 text not null check(snapshot_sha256 ~ '^[0-9a-f]{64}$'),
    captured_at timestamptz not null,
    applied_at timestamptz not null default clock_timestamp(),
    counts jsonb not null check(jsonb_typeof(counts)='object'),
    unique(database_epoch,issuer,revision)
);
create table identity_sync_sources (
    database_epoch uuid not null,
    issuer text not null,
    revision bigint not null default 0 check(revision between 0 and 9007199254740991),
    captured_at timestamptz,
    operation_id uuid references identity_sync_runs(id),
    primary key(database_epoch,issuer),
    check((revision=0 and captured_at is null and operation_id is null)
        or (revision>0 and captured_at is not null and operation_id is not null))
);
comment on table identity_sync_runs is 'Offline trusted identity synchronization receipts; no token, subject list or membership snapshot is retained.';
commit;
