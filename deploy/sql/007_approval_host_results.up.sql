alter table approvals
    add column host_state text check (host_state in (
        'approved', 'denied', 'consumed', 'settled', 'expired', 'cancelled', 'invalidated', 'outcome_unknown'
    )),
    add column execution_outcome text check (execution_outcome in ('succeeded', 'failed', 'cancelled')),
    add column host_updated_at timestamptz,
    add constraint approvals_host_result_required check (
        (host_state is null and execution_outcome is null and host_updated_at is null)
        or (host_state is not null and host_updated_at is not null and (
            (host_state = 'settled' and execution_outcome is not null)
            or (host_state <> 'settled' and execution_outcome is null)
        ))
    ),
    add constraint approvals_host_allow_required check (
        host_state is null or host_state not in ('approved', 'consumed', 'settled', 'outcome_unknown')
        or (decision is not null and decision = 'allow_once')
    ),
    add constraint approvals_host_deny_required check (
        host_state is null or host_state <> 'denied' or (decision is not null and decision = 'reject')
    );

drop index approvals_runtime_active;
create index approvals_runtime_active on approvals (runtime_id, expires_at)
    where state in ('pending', 'decision_received') or (state = 'allowed' and host_state = 'consumed');
comment on column approvals.host_state is 'Host journal fact; never a resumable callback or execution permission.';
comment on column approvals.execution_outcome is 'Observed final native result; approval allowed alone does not imply tool success.';
