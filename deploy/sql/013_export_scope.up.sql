begin;

alter table file_exports add column origin text not null default 'legacy_unverified'
    check (origin in ('session_attachment','workspace_artifact','legacy_unverified'));
alter table file_exports add column workspace_id uuid references workspaces(id);
alter table file_exports add constraint export_origin_workspace check
    ((origin='workspace_artifact' and workspace_id is not null) or (origin<>'workspace_artifact' and workspace_id is null));

-- Previous provenance did not distinguish workspace-wide artifacts from exact
-- session attachments. It cannot imply the stronger workspace authorization.
update files set state='expired' where id in (select file_id from file_exports);
update file_scan_attempts set state='abandoned',finished_at=clock_timestamp()
    where state='active' and file_id in (select file_id from file_exports);

commit;
