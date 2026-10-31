begin;

-- Never erase a native child or the original command's idempotency evidence.
do $$
begin
    if exists (select 1 from commands where action = 'session.fork'
        or child_session_id is not null or fork_outcome is not null) then
        raise exception '042 rollback requires reconciliation of session fork commands';
    end if;
end
$$;

alter table commands
    drop constraint commands_fork_settled,
    drop constraint commands_fork_persisted_child,
    drop constraint commands_fork_outcome_shape,
    drop constraint commands_fork_target,
    drop constraint commands_fork_fields_action,
    drop constraint commands_action_check,
    drop column fork_outcome,
    drop column child_session_id;
alter table commands add constraint commands_action_check check
    (action in ('message.submit','session.cancel','session.archive','session.create','question.answer','session.model.select'));

commit;
