begin;
alter table commands drop constraint commands_action_check;
alter table commands add constraint commands_action_check check
    (action in ('message.submit','session.cancel','session.archive','session.create','question.answer','session.model.select'));
commit;
