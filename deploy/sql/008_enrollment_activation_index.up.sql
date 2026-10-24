-- Authorization checks pending/terminal enrollment state even under an already
-- active shared host/installation. Approved history need not fill this index.
create index enrollments_unapproved_runtime_idx on enrollments(runtime_id)
where state <> 'approved';
