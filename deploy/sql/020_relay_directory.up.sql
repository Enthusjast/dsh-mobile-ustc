-- Transient routing metadata only. A row is useful only while both the exact
-- runtime connection and the exact dispatcher incarnation remain current.
alter table control_consumers add column relay_origin text;
create table relay_runtime_routes (
    runtime_id uuid primary key references runtimes(id) on delete cascade,
    node_id uuid not null references control_consumers(node_id) on delete cascade,
    generation uuid not null,
    runtime_epoch uuid not null,
    connection_id uuid not null
);
create index relay_runtime_routes_node on relay_runtime_routes(node_id,generation);
comment on table relay_runtime_routes is
    'Rebuildable connection directory, never command acceptance or authorization. Compare node generation, epoch and connection before use or deletion.';
