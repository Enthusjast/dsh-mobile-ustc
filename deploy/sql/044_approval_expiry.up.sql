begin;
create index approvals_active_expiry on approvals
    (runtime_id,least(expires_at,coalesce(decision_expires_at,expires_at)),id)
    where metadata_version=1 and
        (state in ('pending','decision_received') or (state='allowed' and host_state='consumed'));
commit;
