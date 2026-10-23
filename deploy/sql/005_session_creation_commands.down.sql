-- Pending creation commands cannot fit the previous schema; never discard
-- their idempotency or unknown-outcome evidence during a rollback.
do $$
begin
    if exists (select 1 from commands where workspace_id is not null) then
        raise exception '005 rollback requires reconciliation of session creation commands';
    end if;
end
$$;
drop index commands_workspace_state;
alter table commands
    drop constraint commands_target_required,
    drop constraint commands_workspace_fk,
    drop constraint commands_runtime_fk,
    drop column workspace_id;
alter table commands alter column session_id set not null;
