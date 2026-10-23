-- Creation commands exist before their native session and retain their
-- authorized workspace target after a successful creation.
alter table commands alter column session_id drop not null;
alter table commands add column workspace_id uuid;
alter table commands
    add constraint commands_runtime_fk foreign key (runtime_id) references runtimes(id),
    add constraint commands_workspace_fk foreign key (runtime_id, workspace_id) references workspaces(runtime_id, id),
    add constraint commands_target_required check (session_id is not null or workspace_id is not null);
create index commands_workspace_state on commands (workspace_id, state, updated_at) where workspace_id is not null;
