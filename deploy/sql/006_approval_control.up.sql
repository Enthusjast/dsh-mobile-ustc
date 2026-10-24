-- Existing rows lack immutable host-connection and assurance bindings. Preserve
-- their audit history, but never turn them into executable version-one requests.
update approvals set state = 'invalidated' where state = 'pending';

alter table approvals
    add column metadata_version integer not null default 0 check (metadata_version in (0, 1)),
    add column runtime_id uuid references runtimes(id),
    add column connection_id uuid,
    add column workspace_id uuid,
    add column nonce_sha256 text check (nonce_sha256 ~ '^[0-9a-f]{64}$'),
    add column assurance_profile text,
    add column max_auth_age_seconds integer check (max_auth_age_seconds between 0 and 900),
    add column request_created_at timestamptz,
    add column decision text check (decision in ('allow_once', 'reject')),
    add column decision_payload_sha256 text check (decision_payload_sha256 ~ '^[0-9a-f]{64}$'),
    add column decision_key_version bigint check (decision_key_version between 1 and 9007199254740991),
    add column decision_approval_key_jkt text,
    add column decision_proof_key_jkt text,
    add column decision_grant_version bigint check (decision_grant_version between 1 and 9007199254740991),
    add column decision_expires_at timestamptz,
    add column authenticated_at timestamptz,
    add column access_token_expires_at timestamptz,
    add constraint approvals_runtime_session_fk foreign key (runtime_id, session_id) references sessions(runtime_id, id),
    add constraint approvals_runtime_workspace_fk foreign key (runtime_id, workspace_id) references workspaces(runtime_id, id),
    add constraint approvals_metadata_v1_required check (metadata_version = 0 or (
        runtime_id is not null and connection_id is not null and workspace_id is not null
        and nonce_sha256 is not null and assurance_profile is not null and max_auth_age_seconds is not null
        and request_created_at is not null and expires_at > request_created_at
        and expires_at <= request_created_at + interval '180 seconds'
        and assurance_profile ~ '^[a-z0-9][a-z0-9./_-]{0,127}$'
        and call_id is null
    )),
    add constraint approvals_decision_v1_required check (metadata_version = 0 or decision is null or (
        decided_by is not null and decided_device_id is not null and decision_jws is not null
        and decision_payload_sha256 is not null and decision_key_version is not null
        and decision_approval_key_jkt is not null and length(decision_approval_key_jkt) = 43
        and decision_proof_key_jkt is not null and length(decision_proof_key_jkt) = 43
        and decision_grant_version is not null and decision_expires_at is not null
        and decision_expires_at <= expires_at and authenticated_at is not null
        and access_token_expires_at is not null and decided_at is not null
    )),
    add constraint approvals_state_v1_consistency check (metadata_version = 0 or (
        (decision is null and state in ('pending', 'expired', 'cancelled', 'invalidated'))
        or (decision is not null and (
            (decision = 'reject' and state = 'denied')
            or (decision = 'allow_once' and state in (
                'decision_received', 'allowed', 'denied', 'expired', 'cancelled', 'invalidated', 'outcome_unknown'
            ))
        ))
    ));

alter table approvals drop constraint approvals_state_check;
alter table approvals add constraint approvals_state_check check (state in (
    'pending', 'decision_received', 'allowed', 'denied', 'expired', 'cancelled', 'invalidated', 'outcome_unknown'
));
update approvals set state = 'outcome_unknown' where metadata_version = 0 and state = 'decision_received';
create unique index approvals_runtime_nonce_unique on approvals (runtime_id, nonce_sha256) where metadata_version = 1;
create unique index approvals_runtime_execution_unique on approvals (runtime_id, execution_id) where metadata_version = 1;
create index approvals_runtime_active on approvals (runtime_id, expires_at) where state in ('pending', 'decision_received');
comment on column approvals.decision_jws is 'Signed decision metadata and context digest only; never full tool arguments.';
comment on column approvals.connection_id is 'Exact host connection that registered the pending execution; reconnects cannot revive it.';
