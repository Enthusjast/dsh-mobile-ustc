begin;
create table command_rate_policy (
    slot integer primary key check(slot=1),
    policy_sha256 bytea not null check(octet_length(policy_sha256)=32),
    policy jsonb not null check(jsonb_typeof(policy)='object'),
    created_at timestamptz not null default clock_timestamp()
);
create table command_rate_counters (
    kind text not null check(kind in('user','device','installation','session')),
    subject_id uuid not null,
    user_id uuid references users(id) on delete cascade,
    device_id uuid references devices(id) on delete cascade,
    installation_id uuid references installations(id) on delete cascade,
    session_id uuid references sessions(id) on delete cascade,
    window_start timestamptz not null default clock_timestamp(),
    used integer not null default 0 check(used between 0 and 100000),
    primary key(kind,subject_id),
    check(num_nonnulls(user_id,device_id,installation_id,session_id)=1),
    check(case kind when 'user' then user_id=subject_id and user_id is not null
        when 'device' then device_id=subject_id and device_id is not null
        when 'installation' then installation_id=subject_id and installation_id is not null
        when 'session' then session_id=subject_id and session_id is not null else false end)
);
comment on table command_rate_counters is
    'Shared command-attempt budgets only. One counter per existing subject, no body, digest, request ID or network address; no execution authority.';
commit;
