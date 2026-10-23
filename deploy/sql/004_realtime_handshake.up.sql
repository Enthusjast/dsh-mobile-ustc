alter table realtime_tickets
    add column device_key_version bigint,
    add column proof_key_thumbprint text;

-- Old pending tickets were issued without a stored key version. Expire them so
-- every ticket used after this migration is bound to the key present at issue.
update realtime_tickets
set consumed_at = coalesce(consumed_at, clock_timestamp());

update realtime_tickets t
set device_key_version = d.key_version,
    proof_key_thumbprint = d.proof_key_thumbprint
from devices d
where d.id = t.device_id;

alter table realtime_tickets
    alter column device_key_version set not null,
    alter column proof_key_thumbprint set not null,
    add constraint realtime_tickets_device_key_version_positive check (device_key_version > 0),
    add constraint realtime_tickets_thumbprint_length check (length(proof_key_thumbprint) = 43);

alter table runtimes
    add column connection_id uuid,
    add column connection_key_version bigint,
    add constraint runtime_connection_key_version_consistency check (
        (connection_id is null and connection_key_version is null)
        or (connection_id is not null and connection_key_version > 0)
    );
create unique index runtimes_connection_id_unique on runtimes (connection_id)
    where connection_id is not null;
