alter table enrollments
    drop constraint if exists enrollments_installation_runtime_fk,
    drop constraint if exists enrollments_owner_request_unique,
    drop constraint if exists enrollments_request_sha256_length,
    drop column if exists runtime_id,
    drop column if exists request_sha256,
    drop column if exists request_id;
