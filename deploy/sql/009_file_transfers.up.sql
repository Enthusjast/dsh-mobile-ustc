begin;

-- Legacy rows have no device-bound registration or scan proof and cannot be
-- exposed by the new transfer service. Keep their metadata for audit/recovery.
update files set state = 'expired';

create table file_transfers (
    file_id uuid primary key references files(id),
    org_id uuid not null references orgs(id),
    runtime_id uuid not null references runtimes(id),
    uploader_device_id uuid not null references devices(id),
    device_key_version bigint not null check (device_key_version > 0),
    proof_key_jkt text not null check (proof_key_jkt ~ '^[A-Za-z0-9_-]{43}$'),
    grant_version bigint not null check (grant_version > 0),
    request_id uuid not null,
    request_sha256 text not null check (request_sha256 ~ '^[0-9a-f]{64}$'),
    quarantine_attempt_id uuid not null,
    committed_attempt_id uuid,
    upload_expires_at timestamptz not null,
    retain_until timestamptz not null,
    scan_ready_at timestamptz not null default clock_timestamp(),
    scan_attempts integer not null default 0 check (scan_attempts >= 0),
    scanner_policy_sha256 text check (scanner_policy_sha256 ~ '^[0-9a-f]{64}$'),
    error_code text check (error_code in ('integrity_mismatch','content_rejected','scan_unavailable','storage_unavailable','access_revoked','expired')),
    quota_released_at timestamptz,
    unique (uploader_device_id, request_id)
);

create table file_quota_usage (
    org_id uuid not null references orgs(id),
    kind text not null check (kind in ('organization','session','user')),
    bucket_id uuid not null,
    reserved_bytes bigint not null default 0 check (reserved_bytes >= 0),
    reserved_files bigint not null default 0 check (reserved_files >= 0),
    primary key (org_id, kind, bucket_id)
);

create table file_scan_attempts (
    id uuid primary key,
    file_id uuid not null references file_transfers(file_id),
    lease_id uuid not null,
    lease_until timestamptz not null,
    scanner_policy_sha256 text not null check (scanner_policy_sha256 ~ '^[0-9a-f]{64}$'),
    state text not null check (state in ('active','abandoned','clean','rejected','failed')),
    created_at timestamptz not null default clock_timestamp(),
    finished_at timestamptz
);
create unique index file_scan_one_active on file_scan_attempts(file_id) where state = 'active';
create index file_scan_lease on file_scan_attempts(lease_until) where state = 'active';
create index files_expiry on files(expires_at) where state <> 'expired';
create index file_transfers_scan_ready on file_transfers(scan_ready_at, file_id) where quota_released_at is null;

create table file_objects (
    file_id uuid not null references file_transfers(file_id),
    kind text not null check (kind in ('quarantine','objects')),
    attempt_id uuid not null,
    object_key text not null unique,
    cleanup_after timestamptz not null,
    lease_id uuid,
    lease_until timestamptz,
    deleted_at timestamptz,
    primary key (file_id, kind, attempt_id),
    check ((lease_id is null) = (lease_until is null))
);
create index file_objects_cleanup on file_objects(cleanup_after);

commit;
