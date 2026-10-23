create table installation_challenges (
    id uuid primary key default gen_random_uuid(),
    installation_id uuid not null references installations(id) on delete cascade,
    key_version bigint not null check (key_version > 0),
    challenge_sha256 bytea not null check (octet_length(challenge_sha256) = 32),
    expires_at timestamptz not null,
    consumed_at timestamptz,
    created_at timestamptz not null default now(),
    check (expires_at > created_at)
);
create index installation_challenges_pending
    on installation_challenges (installation_id, expires_at)
    where consumed_at is null;
create index installation_challenges_recent
    on installation_challenges (installation_id, created_at desc);
comment on table installation_challenges is
    'One-use installation-key challenges; stores only the challenge digest.';

create table host_connection_credentials (
    token_sha256 bytea primary key check (octet_length(token_sha256) = 32),
    installation_id uuid not null references installations(id) on delete cascade,
    key_version bigint not null check (key_version > 0),
    expires_at timestamptz not null,
    revoked_at timestamptz,
    created_at timestamptz not null default now(),
    check (expires_at > created_at)
);
create index host_connection_credentials_active
    on host_connection_credentials (installation_id, expires_at)
    where revoked_at is null;
comment on table host_connection_credentials is
    'Short-lived host connection credentials; stores only SHA-256 token digests and installation key versions.';
