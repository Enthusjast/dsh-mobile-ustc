-- Bind a pending phone confirmation to the device/key version that proved it.
-- Historical rows deliberately remain unbound and must be reconfirmed if pending.
alter table enrollments add column user_confirmed_device_id uuid;
alter table enrollments add column user_confirmed_device_key_version bigint;
alter table enrollments add constraint enrollment_confirmation_device_shape check (
    (user_confirmed_device_id is null and user_confirmed_device_key_version is null)
    or (user_confirmed_by is not null and user_confirmed_device_id is not null
        and user_confirmed_device_key_version is not null and user_confirmed_device_key_version > 0)
);
alter table enrollments add constraint enrollment_confirmation_device_owner
    foreign key (user_confirmed_by, user_confirmed_device_id) references devices(user_id, id);
