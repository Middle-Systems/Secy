--liquibase formatted sql

-- Phase 1 "actionable core": the funnel (KEV-listed OR EPSS > threshold) is evaluated once at
-- alert-generation time and re-evaluated after each KEV/EPSS ingest, and its result is stored on
-- the alert row. That keeps GET /actionable a single indexed scan instead of a per-request join
-- against kev + epss. Mirrors the fields added to
-- net.jdesive.secy.persistence.entity.VulnerabilityAlert.

--changeset secy:004-actionable-enrichment
--comment Actionable funnel, fix state, exploit maturity and alert age on vulnerability_alert

alter table vulnerability_alert add column actionable boolean not null default false;
alter table vulnerability_alert add column actionable_reason varchar(32);

alter table vulnerability_alert add column epss_score float8;
alter table vulnerability_alert add column epss_percentile float8;
alter table vulnerability_alert add column cvss_score float8;

alter table vulnerability_alert add column fix_state varchar(16) not null default 'UNKNOWN';
alter table vulnerability_alert add column fixed_versions varchar(1024);
alter table vulnerability_alert add column fix_source varchar(16);

alter table vulnerability_alert add column exploit_maturity varchar(16) not null default 'NONE';
alter table vulnerability_alert add column kev_due_date date;
alter table vulnerability_alert add column known_ransomware_use varchar(32);

-- Alert age. Pre-existing rows have no recorded birthday; stamp them with the migration time so the
-- column can be NOT NULL, then let the entity's @PrePersist own it from here on.
alter table vulnerability_alert add column created_at timestamp(6);
update vulnerability_alert set created_at = now() where created_at is null;
alter table vulnerability_alert alter column created_at set not null;

-- GET /actionable always filters on `actionable = true` and orders by EPSS desc; the partial index
-- covers both. The reason/severity roll-ups on the dashboard ride the same predicate.
create index idx_vuln_alert_actionable_epss
    on vulnerability_alert (epss_score desc nulls last)
    where actionable;

create index idx_vuln_alert_actionable_created_at
    on vulnerability_alert (created_at)
    where actionable;

-- "Past KEV due date" tile.
create index idx_vuln_alert_kev_due_date
    on vulnerability_alert (kev_due_date)
    where actionable and kev_due_date is not null;

--rollback drop index if exists idx_vuln_alert_kev_due_date;
--rollback drop index if exists idx_vuln_alert_actionable_created_at;
--rollback drop index if exists idx_vuln_alert_actionable_epss;
--rollback alter table vulnerability_alert drop column if exists created_at;
--rollback alter table vulnerability_alert drop column if exists known_ransomware_use;
--rollback alter table vulnerability_alert drop column if exists kev_due_date;
--rollback alter table vulnerability_alert drop column if exists exploit_maturity;
--rollback alter table vulnerability_alert drop column if exists fix_source;
--rollback alter table vulnerability_alert drop column if exists fixed_versions;
--rollback alter table vulnerability_alert drop column if exists fix_state;
--rollback alter table vulnerability_alert drop column if exists cvss_score;
--rollback alter table vulnerability_alert drop column if exists epss_percentile;
--rollback alter table vulnerability_alert drop column if exists epss_score;
--rollback alter table vulnerability_alert drop column if exists actionable_reason;
--rollback alter table vulnerability_alert drop column if exists actionable;
