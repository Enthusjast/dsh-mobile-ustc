begin;
create table command_rate_policy_changes (
    operation_id uuid primary key,
    database_epoch uuid not null,
    policy_slot integer not null default 1 references command_rate_policy(slot) check(policy_slot=1),
    previous_sha256 bytea not null check(octet_length(previous_sha256)=32),
    policy_sha256 bytea not null check(octet_length(policy_sha256)=32),
    policy jsonb not null check(jsonb_typeof(policy)='object'),
    changed_at timestamptz not null default clock_timestamp(),
    check(previous_sha256<>policy_sha256)
);
create function command_rate_change_immutable() returns trigger language plpgsql as $$ begin
    raise exception 'command rate policy change evidence is immutable' using errcode='23514';
end $$;
create trigger command_rate_change_immutable before update or delete on command_rate_policy_changes
    for each row execute function command_rate_change_immutable();
commit;
