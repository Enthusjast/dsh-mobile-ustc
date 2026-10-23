-- This migration runs before enrollment endpoints are enabled. Existing rows
-- cannot be associated with a profile/request digest automatically.
do $$
begin
    if exists (select 1 from enrollments) then
        raise exception '002_enrollment_runtime requires manual reconciliation of existing enrollment rows';
    end if;
end
$$;

alter table enrollments add column request_id uuid;
alter table enrollments add column request_sha256 bytea;
alter table enrollments add column runtime_id uuid;

alter table enrollments alter column request_id set not null;
alter table enrollments alter column request_sha256 set not null;
alter table enrollments alter column runtime_id set not null;

alter table enrollments
    add constraint enrollments_request_sha256_length check (octet_length(request_sha256) = 32),
    add constraint enrollments_owner_request_unique unique (requested_by, request_id),
    add constraint enrollments_installation_runtime_fk
        foreign key (installation_id, runtime_id) references runtimes(installation_id, id);
