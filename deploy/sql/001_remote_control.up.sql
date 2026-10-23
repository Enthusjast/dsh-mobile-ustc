create extension if not exists pgcrypto;

create table orgs (
    id uuid primary key default gen_random_uuid(),
    slug text not null unique,
    name text not null,
    created_at timestamptz not null default now()
);

create table users (
    id uuid primary key default gen_random_uuid(),
    issuer text not null,
    subject text not null,
    status text not null default 'active'
        check (status in ('active', 'suspended', 'deleted')),
    created_at timestamptz not null default now(),
    unique (issuer, subject)
);

create table org_memberships (
    org_id uuid not null references orgs(id),
    user_id uuid not null references users(id),
    role text not null check (role in ('member', 'admin')),
    created_at timestamptz not null default now(),
    primary key (org_id, user_id)
);

create table devices (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references users(id),
    name text not null check (length(name) between 1 and 160),
    approval_public_jwk jsonb not null check (jsonb_typeof(approval_public_jwk) = 'object'),
    approval_key_thumbprint text not null unique,
    proof_public_jwk jsonb not null check (jsonb_typeof(proof_public_jwk) = 'object'),
    proof_key_thumbprint text not null unique,
    key_version bigint not null default 1 check (key_version > 0),
    push_provider text check (push_provider in ('fcm', 'vendor') or push_provider is null),
    push_token_ciphertext bytea,
    last_seen_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz not null default now(),
    unique (user_id, id),
    check (approval_key_thumbprint <> proof_key_thumbprint)
);

create table hosts (
    id uuid primary key default gen_random_uuid(),
    org_id uuid not null references orgs(id),
    alias text not null check (length(alias) between 1 and 160),
    state text not null default 'pending'
        check (state in ('pending', 'active', 'revoked')),
    created_at timestamptz not null default now(),
    unique (org_id, id)
);

create table installations (
    id uuid primary key default gen_random_uuid(),
    host_id uuid not null references hosts(id),
    owner_user_id uuid not null references users(id),
    public_jwk jsonb not null check (jsonb_typeof(public_jwk) = 'object'),
    key_version bigint not null default 1 check (key_version > 0),
    public_key_thumbprint text not null unique,
    revoked_at timestamptz,
    created_at timestamptz not null default now(),
    unique (host_id, id)
);

create table enrollments (
    id uuid primary key default gen_random_uuid(),
    host_id uuid not null references hosts(id),
    installation_id uuid not null references installations(id),
    requested_by uuid not null references users(id),
    code_hash bytea not null unique,
    state text not null default 'pending'
        check (state in ('pending', 'user_confirmed', 'approved', 'denied', 'expired', 'cancelled')),
    expires_at timestamptz not null,
    user_confirmed_by uuid references users(id),
    user_confirmed_at timestamptz,
    host_confirmed_at timestamptz,
    decided_by uuid references users(id),
    decided_at timestamptz,
    created_at timestamptz not null default now(),
    check (expires_at > created_at)
);
create index enrollments_pending on enrollments (expires_at) where state in ('pending', 'user_confirmed');

create table runtimes (
    id uuid primary key default gen_random_uuid(),
    installation_id uuid not null references installations(id),
    profile_ref text not null check (length(profile_ref) between 1 and 512),
    epoch uuid,
    dsh_version text,
    application_version text,
    plugin_version text,
    protocol_version integer not null default 1 check (protocol_version > 0),
    last_seen_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz not null default now(),
    unique (installation_id, profile_ref),
    unique (installation_id, id)
);

create table runtime_grants (
    runtime_id uuid not null references runtimes(id),
    user_id uuid not null references users(id),
    role text not null check (role in ('viewer', 'operator', 'owner')),
    scope jsonb not null check (
        jsonb_typeof(scope) = 'object'
        and scope ?& array['actions', 'workspaces', 'sessions']
        and scope - 'actions' - 'workspaces' - 'sessions' = '{}'::jsonb
        and jsonb_typeof(scope->'actions') = 'array'
        and jsonb_typeof(scope->'workspaces') = 'array'
        and jsonb_typeof(scope->'sessions') = 'array'
    ),
    grant_version bigint not null default 1 check (grant_version > 0),
    granted_by uuid not null references users(id),
    expires_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz not null default now(),
    primary key (runtime_id, user_id)
);
create index runtime_grants_user_active on runtime_grants (user_id, runtime_id) where revoked_at is null;
comment on column runtime_grants.scope is
    'Explicit JSON object: actions, workspaces and sessions arrays; empty arrays grant no access.';

create table workspaces (
    id uuid primary key default gen_random_uuid(),
    runtime_id uuid not null references runtimes(id),
    workspace_ref text not null check (length(workspace_ref) between 1 and 512),
    created_at timestamptz not null default now(),
    unique (runtime_id, workspace_ref),
    unique (runtime_id, id)
);
comment on column workspaces.workspace_ref is
    'Opaque runtime-owned workspace identity; never a host filesystem path.';

create table sessions (
    id uuid primary key default gen_random_uuid(),
    runtime_id uuid not null references runtimes(id),
    workspace_id uuid,
    dsh_session_id text not null check (length(dsh_session_id) between 1 and 2048),
    state text not null default 'available'
        check (state in ('available', 'running', 'archived', 'unavailable')),
    last_persisted_seq bigint not null default -1 check (last_persisted_seq >= -1),
    updated_at timestamptz not null default now(),
    created_at timestamptz not null default now(),
    unique (runtime_id, dsh_session_id),
    unique (runtime_id, id),
    foreign key (runtime_id, workspace_id) references workspaces(runtime_id, id)
);
create index sessions_runtime_updated on sessions (runtime_id, updated_at desc, id);

create table commands (
    device_id uuid not null references devices(id),
    request_id uuid not null,
    user_id uuid not null references users(id),
    runtime_id uuid not null,
    session_id uuid not null,
    payload_sha256 text not null check (payload_sha256 ~ '^[0-9a-f]{64}$'),
    state text not null check (state in (
        'received', 'host_accepted', 'dispatching', 'agent_queued', 'observed',
        'settled', 'rejected', 'outcome_unknown'
    )),
    updated_at timestamptz not null default now(),
    created_at timestamptz not null default now(),
    primary key (device_id, request_id),
    foreign key (user_id, device_id) references devices(user_id, id),
    foreign key (runtime_id, session_id) references sessions(runtime_id, id)
);
create index commands_session_state on commands (session_id, state, updated_at);

create table approvals (
    id uuid primary key,
    session_id uuid not null references sessions(id),
    runtime_epoch uuid not null,
    execution_id uuid not null,
    call_id text,
    binding_sha256 text not null check (binding_sha256 ~ '^[0-9a-f]{64}$'),
    policy_version bigint not null check (policy_version > 0),
    state text not null check (state in (
        'pending', 'decision_received', 'allowed', 'denied',
        'expired', 'cancelled', 'invalidated'
    )),
    decided_by uuid references users(id),
    decided_device_id uuid references devices(id),
    decision_jws text,
    expires_at timestamptz not null,
    created_at timestamptz not null default now(),
    decided_at timestamptz,
    unique (session_id, runtime_epoch, execution_id),
    check (expires_at > created_at)
);
create index approvals_pending on approvals (expires_at) where state = 'pending';

create table files (
    id uuid primary key default gen_random_uuid(),
    session_id uuid not null references sessions(id),
    uploader_id uuid not null references users(id),
    direction text not null check (direction in ('to_host', 'from_host')),
    name text not null check (length(name) between 1 and 512),
    size_bytes bigint not null check (size_bytes >= 0),
    sha256 text not null check (sha256 ~ '^[0-9a-f]{64}$'),
    object_key text not null unique,
    state text not null check (state in ('uploading', 'scanning', 'clean', 'rejected', 'expired')),
    expires_at timestamptz not null,
    created_at timestamptz not null default now(),
    check (expires_at > created_at)
);

create table audit_log (
    id bigint generated always as identity primary key,
    ts timestamptz not null default now(),
    org_id uuid references orgs(id),
    actor_type text not null check (actor_type in ('user', 'device', 'installation', 'system')),
    actor_id text not null,
    device_id uuid references devices(id),
    runtime_id uuid references runtimes(id),
    session_id uuid references sessions(id),
    action text not null,
    result text not null,
    metadata jsonb not null default '{}'::jsonb check (jsonb_typeof(metadata) = 'object')
);
create index audit_org_time on audit_log (org_id, ts desc);

create table control_outbox (
    id uuid primary key default gen_random_uuid(),
    org_id uuid references orgs(id),
    topic text not null,
    payload jsonb not null check (jsonb_typeof(payload) = 'object'),
    created_at timestamptz not null default now(),
    published_at timestamptz
);
create index control_outbox_pending on control_outbox (created_at, id) where published_at is null;

create table app_releases (
    id uuid primary key default gen_random_uuid(),
    platform text not null,
    version text not null,
    version_code bigint not null check (version_code > 0),
    sha256 text not null check (sha256 ~ '^[0-9a-f]{64}$'),
    object_key text not null,
    rollout integer not null default 0 check (rollout between 0 and 100),
    mandatory boolean not null default false,
    notes text not null default '',
    created_at timestamptz not null default now(),
    unique (platform, version_code)
);
