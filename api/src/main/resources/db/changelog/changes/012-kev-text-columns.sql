--liquibase formatted sql

-- CISA's KEV catalog entries carry free-text prose (description, required action, notes) with no
-- documented length cap. The 004-era varchar(1024) columns were a guess from the ddl-auto=update
-- baseline and a real ingest hit it: `value too long for type character varying(1024)` inserting
-- kev.required_actions (a real entry's remediation guidance ran well past 1024 chars). description
-- and notes are the same kind of unbounded external prose, so all three widen to `text` rather than
-- picking another arbitrary cap that just fails again on a future KEV update.

--changeset secy:012-kev-text-columns
--comment Widen kev.description/required_actions/notes from varchar(1024) to text (unbounded, CISA prose has no documented length cap)

alter table kev alter column description type text;
alter table kev alter column required_actions type text;
alter table kev alter column notes type text;

--rollback alter table kev alter column notes type varchar(1024);
--rollback alter table kev alter column required_actions type varchar(1024);
--rollback alter table kev alter column description type varchar(1024);
