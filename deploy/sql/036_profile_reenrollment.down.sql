begin;
-- Refuse rollback once a profile name has historical duplicates. Never rename
-- or delete historical runtime identities to fit the older constraint.
alter table runtimes add constraint runtimes_installation_id_profile_ref_key
    unique(installation_id,profile_ref);
drop index runtimes_live_installation_profile;
commit;
