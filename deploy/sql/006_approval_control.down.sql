-- Rollback cannot restore the validity of old pending requests. Preserve ended
-- records, mapping the newer uncertain state to a nonexecutable legacy state.
update approvals set state = 'invalidated' where state in ('pending', 'decision_received', 'outcome_unknown');
drop index approvals_runtime_active;
drop index approvals_runtime_execution_unique;
drop index approvals_runtime_nonce_unique;
alter table approvals drop constraint approvals_state_check;
alter table approvals add constraint approvals_state_check check (state in (
    'pending', 'decision_received', 'allowed', 'denied', 'expired', 'cancelled', 'invalidated'
));
alter table approvals
    drop constraint approvals_state_v1_consistency,
    drop constraint approvals_decision_v1_required,
    drop constraint approvals_metadata_v1_required,
    drop constraint approvals_runtime_workspace_fk,
    drop constraint approvals_runtime_session_fk,
    drop column access_token_expires_at,
    drop column authenticated_at,
    drop column decision_expires_at,
    drop column decision_grant_version,
    drop column decision_proof_key_jkt,
    drop column decision_approval_key_jkt,
    drop column decision_key_version,
    drop column decision_payload_sha256,
    drop column decision,
    drop column request_created_at,
    drop column max_auth_age_seconds,
    drop column assurance_profile,
    drop column nonce_sha256,
    drop column workspace_id,
    drop column connection_id,
    drop column runtime_id,
    drop column metadata_version;
