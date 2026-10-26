begin;

-- The lookup key is stable across encryption-key rotation; changing it silently
-- would defeat the active-address uniqueness boundary.
create table push_key_metadata (
    slot integer primary key check (slot=1),
    lookup_key_sha256 text not null check (lookup_key_sha256 ~ '^[0-9a-f]{64}$')
);
create table push_bindings (
    id uuid primary key,
    org_id uuid not null references orgs(id),
    user_id uuid not null references users(id),
    device_id uuid not null references devices(id),
    device_key_version bigint not null check (device_key_version>0),
    proof_key_jkt text not null check (proof_key_jkt ~ '^[A-Za-z0-9_-]{43}$'),
    provider text not null check (provider='fcm'),
    provider_project text not null,
    address_sha256 text not null check (address_sha256 ~ '^[0-9a-f]{64}$'),
    address_ciphertext bytea,
    request_sha256 text not null check (request_sha256 ~ '^[0-9a-f]{64}$'),
    revoke_sha256 text not null check (revoke_sha256 ~ '^[0-9a-f]{64}$'),
    challenge_sha256 text not null check (challenge_sha256 ~ '^[0-9a-f]{64}$'),
    challenge_expires_at timestamptz not null,
    expires_at timestamptz not null,
    state text not null check (state in ('pending','active','disabled','expired')),
    created_at timestamptz not null default clock_timestamp(),
    activated_at timestamptz,
    check (challenge_expires_at>created_at and expires_at>=challenge_expires_at),
    check (state in ('disabled','expired') or address_ciphertext is not null)
);
create unique index push_active_address on push_bindings(provider,provider_project,address_sha256) where state='active';
create unique index push_active_device_org on push_bindings(device_id,org_id) where state='active';
create index push_binding_expiry on push_bindings(expires_at) where state in ('pending','active');
create index push_device_bindings on push_bindings(device_id,created_at);

create table push_deliveries (
    id uuid primary key default gen_random_uuid(),
    binding_id uuid not null references push_bindings(id),
    kind text not null check (kind in ('challenge','approval','question','timed_question')),
    source_id uuid,
    runtime_id uuid references runtimes(id),
    runtime_epoch uuid,
    session_id uuid references sessions(id),
    grant_version bigint,
    nonce_ciphertext bytea,
    state text not null default 'queued' check (state in ('queued','leased','retry','provider_accepted','confirmed','failed','expired')),
    attempts integer not null default 0 check (attempts>=0),
    next_attempt_at timestamptz not null default clock_timestamp(),
    expires_at timestamptz not null,
    lease_id uuid,
    lease_until timestamptz,
    provider_message_sha256 text check (provider_message_sha256 ~ '^[0-9a-f]{64}$'),
    error_code text check (error_code ~ '^[a-z][a-z_]{0,63}$'),
    created_at timestamptz not null default clock_timestamp(),
    updated_at timestamptz not null default clock_timestamp(),
    check (expires_at>created_at),
    check ((kind='challenge' and source_id is null and runtime_id is null and session_id is null and runtime_epoch is null and grant_version is null)
        or (kind<>'challenge' and source_id is not null and runtime_id is not null and session_id is not null and runtime_epoch is not null and grant_version>0)),
    unique(binding_id,kind,source_id)
);
create unique index push_one_challenge on push_deliveries(binding_id) where kind='challenge';
create index push_dispatch_queue on push_deliveries(next_attempt_at,created_at) where state in ('queued','retry','leased');
create index push_delivery_expiry on push_deliveries(expires_at);
create table push_receipts (
    notification_id uuid not null references push_deliveries(id),
    state text not null check (state in ('posted','opened','blocked')),
    received_at timestamptz not null default clock_timestamp(),
    primary key(notification_id,state)
);
-- Superseded legacy placeholders never authorize a new channel.
update devices set push_provider=null,push_token_ciphertext=null;
commit;
