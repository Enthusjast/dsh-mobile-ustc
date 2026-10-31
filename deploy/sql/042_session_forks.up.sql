begin;

alter table commands
    add column child_session_id uuid,
    add column fork_outcome jsonb;

-- A known native child can outlive an unavailable checkpoint/catalog. Do not
-- add a child foreign key that would discard that recovery evidence.
alter table commands drop constraint commands_action_check;
alter table commands add constraint commands_action_check check
    (action in ('message.submit','session.cancel','session.archive','session.create','question.answer','session.model.select','session.fork'));

alter table commands
    add constraint commands_fork_fields_action check (
        action is not distinct from 'session.fork'
        or (child_session_id is null and fork_outcome is null)
    ),
    add constraint commands_fork_target check (
        action is distinct from 'session.fork'
        or (session_id is not null and workspace_id is not null
            and (child_session_id is null or child_session_id <> session_id)
            and state not in ('agent_queued','observed'))
    ),
    add constraint commands_fork_outcome_shape check (
        fork_outcome is null or coalesce(
            jsonb_typeof(fork_outcome) = 'object'
            and fork_outcome ?& array['v','workspace_attachment','checkpoint']
            and fork_outcome - array['v','workspace_attachment','checkpoint'] = '{}'::jsonb
            and fork_outcome->'v' = '1'::jsonb
            and fork_outcome->'workspace_attachment' in ('"attached"'::jsonb,'"failed"'::jsonb,'"unknown"'::jsonb)
            and fork_outcome->'checkpoint' in ('"persisted"'::jsonb,'"unavailable"'::jsonb,'"failed"'::jsonb,'"unknown"'::jsonb), false)
    ),
    add constraint commands_fork_persisted_child check (
        fork_outcome is null or fork_outcome->>'checkpoint' <> 'persisted' or child_session_id is not null
    ),
    add constraint commands_fork_settled check (
        action is distinct from 'session.fork' or state <> 'settled'
        or (child_session_id is not null and fork_outcome is not null
            and fork_outcome->>'checkpoint' = 'persisted')
    );

commit;
