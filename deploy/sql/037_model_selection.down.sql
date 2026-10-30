begin;
-- Refuse to erase or reclassify model-selection command evidence for rollback.
alter table commands drop constraint commands_action_check;
alter table commands add constraint commands_action_check check
    (action in ('message.submit','session.cancel','session.archive','session.create','question.answer'));
commit;
