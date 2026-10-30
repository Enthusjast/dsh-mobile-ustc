begin;
create index installations_owner_directory on installations(owner_user_id,created_at desc,id desc);
drop index control_outbox_retention;
create index control_outbox_retention on control_outbox(created_at,id)
    where topic in ('device.revoked','runtime.revoked','runtime_grant.updated','runtime_grant.revoked','approval.pending','approval.decided',
        'approval.ended','approval.result','approval.authorization.prepared','approval.device.revoked');
commit;
