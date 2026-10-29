-- Dropping captured device bindings would weaken enrollment authorization.
do $$
begin
    if exists (select 1 from enrollments where user_confirmed_device_id is not null) then
        raise exception 'enrollment device confirmations prevent destructive rollback';
    end if;
end $$;
alter table enrollments drop constraint enrollment_confirmation_device_owner;
alter table enrollments drop constraint enrollment_confirmation_device_shape;
alter table enrollments drop column user_confirmed_device_key_version;
alter table enrollments drop column user_confirmed_device_id;
