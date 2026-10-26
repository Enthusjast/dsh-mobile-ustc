begin;
-- Legacy digests do not prove their original action. Leave them unclassified.
alter table commands add column action text check (action in ('message.submit','session.cancel','session.archive','session.create','question.answer'));
commit;
