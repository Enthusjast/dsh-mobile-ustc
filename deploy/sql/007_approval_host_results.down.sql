-- Older code cannot distinguish a spent permit from a completed execution.
-- Preserve uncertainty and all audit/outbox facts; never revive it as pending.
update approvals set state = 'outcome_unknown' where host_state = 'consumed';
drop index approvals_runtime_active;
create index approvals_runtime_active on approvals (runtime_id, expires_at) where state in ('pending', 'decision_received');
alter table approvals
    drop constraint approvals_host_deny_required,
    drop constraint approvals_host_allow_required,
    drop constraint approvals_host_result_required,
    drop column host_updated_at,
    drop column execution_outcome,
    drop column host_state;
