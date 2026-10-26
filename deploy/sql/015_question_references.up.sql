begin;
create table question_reference_feeds (
    runtime_id uuid primary key references runtimes(id),
    runtime_epoch uuid not null,
    connection_id uuid not null,
    key_version bigint not null check (key_version>0),
    sequence bigint not null check (sequence between 0 and 9007199254740991),
    snapshot_sha256 text not null check (snapshot_sha256 ~ '^[0-9a-f]{64}$'),
    lease_until timestamptz not null,
    updated_at timestamptz not null default clock_timestamp()
);
create table question_references (
    id uuid primary key,
    runtime_id uuid not null references runtimes(id),
    runtime_epoch uuid not null,
    connection_id uuid not null,
    session_id uuid not null references sessions(id),
    kind text not null check (kind in ('question','timed_question')),
    state text not null check (state in ('pending','continued','reply_queued','ended')),
    expires_at timestamptz,
    created_at timestamptz not null default clock_timestamp(),
    updated_at timestamptz not null default clock_timestamp(),
    check (kind<>'question' or (state in ('pending','ended') and expires_at is not null)),
    check (state not in ('continued','reply_queued') or (kind='timed_question' and expires_at is null))
);
create index question_reference_source on question_references(runtime_id,runtime_epoch,state);
create index question_reference_budget on question_references(runtime_id,created_at);
create index question_reference_retention on question_references(runtime_id,updated_at) where state='ended';
commit;
