begin;
create table realtime_connection_policy (
    slot integer primary key check(slot=1),
    policy_sha256 bytea not null check(octet_length(policy_sha256)=32),
    policy jsonb not null check(jsonb_typeof(policy)='object'),
    admission_tick uuid not null default gen_random_uuid()
);
create table realtime_device_connections (
    connection_id uuid primary key,
    node_id uuid not null references control_consumers(node_id) on delete cascade,
    generation uuid not null,
    user_id uuid not null references users(id) on delete cascade,
    device_id uuid not null references devices(id) on delete cascade,
    installation_id uuid not null references installations(id) on delete cascade,
    runtime_id uuid not null references runtimes(id) on delete cascade,
    expires_at timestamptz not null
);
create index realtime_device_connections_node on realtime_device_connections(node_id,generation);
create index realtime_device_connections_expiry on realtime_device_connections(expires_at,connection_id);
comment on table realtime_device_connections is
    'Authenticated device socket occupancy only; current consumer generation/lease and socket expiry fence each row. Never a bearer credential or command authority.';
commit;
