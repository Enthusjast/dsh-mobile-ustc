create table dpop_proof_resources (
    scope_sha256 bytea primary key check (octet_length(scope_sha256)=32),
    entries_per_bucket integer not null check (entries_per_bucket between 64 and 65536),
    created_at timestamptz not null default clock_timestamp()
);

create table dpop_proof_buckets (
    scope_sha256 bytea not null references dpop_proof_resources(scope_sha256),
    bucket smallint not null check (bucket between 0 and 255),
    entry_count integer not null default 0 check (entry_count between 0 and 65536),
    last_cleanup_at timestamptz not null default clock_timestamp(),
    primary key(scope_sha256,bucket)
);
create index dpop_proof_cleanup_order on dpop_proof_buckets(scope_sha256,last_cleanup_at,bucket);

create table dpop_proof_entries (
    scope_sha256 bytea not null,
    bucket smallint not null,
    kind smallint not null check (kind in (0,1)),
    entry_sha256 bytea not null check (octet_length(entry_sha256)=32),
    expires_at timestamptz not null,
    primary key(scope_sha256,bucket,kind,entry_sha256),
    foreign key(scope_sha256,bucket) references dpop_proof_buckets(scope_sha256,bucket)
);
create index dpop_proof_expiry on dpop_proof_entries(scope_sha256,bucket,expires_at);
comment on table dpop_proof_entries is
    'Shared one-use DPoP nonce/replay digests only; no raw nonce, jti, token or identity. Bucket locking makes rotation atomic across processes.';
