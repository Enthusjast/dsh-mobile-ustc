begin;
-- A local profile reference is a name, not an authority identifier. Preserve
-- retired runtime UUIDs while permitting a fresh, independently bound runtime.
alter table runtimes drop constraint runtimes_installation_id_profile_ref_key;
create unique index runtimes_live_installation_profile
    on runtimes(installation_id,profile_ref) where revoked_at is null;
commit;
