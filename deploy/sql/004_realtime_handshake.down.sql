drop index runtimes_connection_id_unique;
alter table runtimes drop column connection_id;
alter table realtime_tickets
    drop constraint realtime_tickets_device_key_version_positive,
    drop constraint realtime_tickets_thumbprint_length,
    drop column device_key_version,
    drop column proof_key_thumbprint;
