--liquibase formatted sql

-- Phase 5 — Compliance (Docker / CIS) (ROADMAP.md).
--
-- The architecture call this phase makes: a compliance report's VULNERABILITY half is routed through
-- the Phase 4 asset pipeline (asset -> asset_component -> vulnerability_alert -> enrichment ->
-- GET /actionable), and its MISCONFIGURATION half stays its own concept.
--
-- Why the vulnerability half moves. docker_compliance_report_vulnerability rows are literally
-- `trivy image` findings -- package, installed version, FixedVersion, CVE id -- and they were being
-- turned into docker_vulnerabitity_alert rows that had no FK to `vulnerabilities` at all. No CVE
-- join means no EPSS, no KEV, no exploit maturity and no CVSS, which means no funnel, no ranking and
-- no /actionable. That table has been outside the product's primary screen since before Phase 1 and
-- is named as the cautionary tale in 009's own header. Phase 4 already built the pipeline these
-- findings need; Phase 5 stops routing around it.
--
-- Why the misconfiguration half does NOT move. A benchmark control has no CVE, so every input the
-- actionable funnel ranks on is structurally absent. Forcing controls into vulnerability_alert would
-- mean either fabricating those columns or parking a permanently-null second class of row on the
-- primary screen. Controls get their own (restored) control table instead.

--changeset secy:010a-compliance-report-asset
-- What the report audited, and the row its vulnerability alerts hang off. Nullable in the schema
-- because pre-Phase-5 rows have no asset; the upload path never creates one without.
alter table docker_compliance_report add column asset_id uuid;
alter table docker_compliance_report add column status varchar(32);
alter table docker_compliance_report add column pending_raw_body text;
alter table docker_compliance_report add column job_id uuid;
alter table docker_compliance_report add column passed_controls integer not null default 0;
alter table docker_compliance_report add column failed_controls integer not null default 0;
alter table docker_compliance_report add column skipped_controls integer not null default 0;
alter table docker_compliance_report add column scanned_at timestamp(6);
alter table docker_compliance_report add column created_at timestamp(6);

update docker_compliance_report set created_at = now() where created_at is null;
alter table docker_compliance_report alter column created_at set not null;

-- The description column was varchar(255) while the entity had no length cap; a benchmark preamble
-- overflows it.
alter table docker_compliance_report alter column description type varchar(4096);

alter table docker_compliance_report add constraint fk_docker_compliance_report_asset
    foreign key (asset_id) references asset (id);

create index idx_docker_compliance_report_asset on docker_compliance_report (asset_id);
create index idx_docker_compliance_report_job_id on docker_compliance_report (job_id);
create index idx_docker_compliance_report_created_at on docker_compliance_report (created_at desc);

--rollback drop index if exists idx_docker_compliance_report_created_at;
--rollback drop index if exists idx_docker_compliance_report_job_id;
--rollback drop index if exists idx_docker_compliance_report_asset;
--rollback alter table docker_compliance_report drop constraint if exists fk_docker_compliance_report_asset;
--rollback alter table docker_compliance_report drop column created_at;
--rollback alter table docker_compliance_report drop column scanned_at;
--rollback alter table docker_compliance_report drop column skipped_controls;
--rollback alter table docker_compliance_report drop column failed_controls;
--rollback alter table docker_compliance_report drop column passed_controls;
--rollback alter table docker_compliance_report drop column job_id;
--rollback alter table docker_compliance_report drop column pending_raw_body;
--rollback alter table docker_compliance_report drop column status;
--rollback alter table docker_compliance_report drop column asset_id;

--changeset secy:010b-compliance-controls
-- The layer the old model threw away. Trivy nests
--   Results[] (control) -> results[] (target) -> misconfigurations[] (check)
-- and the pre-Phase-5 ingest flattened straight to the leaves, which made "how many controls pass"
-- -- the one number a compliance screen exists for -- unanswerable.
create table docker_compliance_control (
    id varchar(255) not null,
    report_id varchar(255),
    control_id varchar(64),
    name varchar(255),
    description varchar(4096),
    severity varchar(32),
    status varchar(16) not null,
    failed_checks integer not null default 0,
    primary key (id)
);

alter table docker_compliance_control add constraint fk_docker_compliance_control_report
    foreign key (report_id) references docker_compliance_report (id);

create index idx_docker_compliance_control_report on docker_compliance_control (report_id);

--rollback drop table if exists docker_compliance_control;

--changeset secy:010c-compliance-misconfig-status
-- status: PASS/FAIL/SKIP. Trivy emits a per-check Status which the old model parsed and then dropped
-- on the floor, so a report could only ever be rendered as an undifferentiated bag of findings.
-- Existing rows are FAIL: the pre-Phase-5 ingest only ever stored reported findings, and a reported
-- finding is a failure.
alter table docker_compliance_report_misconfig add column status varchar(16) not null default 'FAIL';
alter table docker_compliance_report_misconfig add column check_id varchar(64);
alter table docker_compliance_report_misconfig add column target varchar(512);
alter table docker_compliance_report_misconfig add column control_id varchar(255);

-- Remediation text and the finding message are prose and do not fit in 255.
alter table docker_compliance_report_misconfig alter column resolution type varchar(4096);
alter table docker_compliance_report_misconfig alter column message type varchar(4096);

alter table docker_compliance_report_misconfig add constraint fk_docker_misconfig_control
    foreign key (control_id) references docker_compliance_control (id);

create index idx_docker_misconfig_control on docker_compliance_report_misconfig (control_id);
create index idx_docker_misconfig_report_status on docker_compliance_report_misconfig (report_id, status);

--rollback drop index if exists idx_docker_misconfig_report_status;
--rollback drop index if exists idx_docker_misconfig_control;
--rollback alter table docker_compliance_report_misconfig drop constraint if exists fk_docker_misconfig_control;
--rollback alter table docker_compliance_report_misconfig drop column control_id;
--rollback alter table docker_compliance_report_misconfig drop column target;
--rollback alter table docker_compliance_report_misconfig drop column check_id;
--rollback alter table docker_compliance_report_misconfig drop column status;

--changeset secy:010d-compliance-vulnerability-identity
-- The latent collision: the primary key WAS the CVE id, so two reports both naming CVE-2021-44228
-- collided and the second silently stole the first report's row (report_id is a plain column on it).
-- The id becomes generated and the CVE moves to its own non-unique column. The extra coordinate
-- columns are what lets POST /compliance/reports/{id}/scan rebuild the exact same identity_key
-- without the raw document -- re-deriving it by guesswork would present "new" components on every
-- re-scan and auto-resolve every alert the upload raised.
alter table docker_compliance_report_vulnerability add column vulnerability_id varchar(64);
alter table docker_compliance_report_vulnerability add column purl varchar(512);
alter table docker_compliance_report_vulnerability add column package_type varchar(64);
alter table docker_compliance_report_vulnerability add column target varchar(512);
alter table docker_compliance_report_vulnerability add column package_path varchar(1024);
alter table docker_compliance_report_vulnerability add column layer varchar(255);

update docker_compliance_report_vulnerability set vulnerability_id = id where vulnerability_id is null;

create index idx_docker_report_vuln_report on docker_compliance_report_vulnerability (report_id);

--rollback drop index if exists idx_docker_report_vuln_report;
--rollback alter table docker_compliance_report_vulnerability drop column layer;
--rollback alter table docker_compliance_report_vulnerability drop column package_path;
--rollback alter table docker_compliance_report_vulnerability drop column target;
--rollback alter table docker_compliance_report_vulnerability drop column package_type;
--rollback alter table docker_compliance_report_vulnerability drop column purl;
--rollback alter table docker_compliance_report_vulnerability drop column vulnerability_id;

--changeset secy:010e-drop-dead-docker-alert-tables
-- docker_vulnerabitity_alert (sic) and docker_misconfiguration_alert were written by
-- GET /cis/docker/scan/{id} and read by absolutely nothing -- no endpoint, no query, no dashboard
-- roll-up, no UI. The vulnerability one is now genuinely superseded: those findings are
-- vulnerability_alert rows on the audited asset, with enrichment and a place in /actionable.
--
-- The misconfiguration one carried dismiss/evidence fields that nothing ever set or read. It is
-- dropped rather than kept because its shape does not survive this phase's model: a compliance report
-- is an append-only dated audit, so a dismissal keyed to one report's misconfig row would be lost on
-- the next upload. Misconfiguration triage belongs to Phase 7, keyed on (asset, check) so it
-- persists across audits -- see the Phase 7 roadmap entry.
drop table if exists docker_vulnerabitity_alert;
drop table if exists docker_misconfiguration_alert;

--rollback create table docker_misconfiguration_alert (id varchar(255) not null, created_date timestamp(6), last_modified_date timestamp(6), dismissed boolean not null, dismissed_reason varchar(255), dismissed_evidence_url varchar(255), misconfiguration_id varchar(255) unique, primary key (id));
--rollback create table docker_vulnerabitity_alert (id varchar(255) not null, created_date timestamp(6), last_modified_date timestamp(6), dismissed boolean not null, dismissed_reason varchar(255), dismissed_evidence_url varchar(255), vulnerability_id varchar(255) unique, primary key (id));

--changeset secy:010f-compliance-scan-job-type
-- COMPLIANCE_SCAN joins SBOM_UPLOAD and ASSET_SCAN as a per-invocation job type: each report is its
-- own unit of work with its own payload (which docker_compliance_report row to finish), so several
-- may be QUEUED/RUNNING at once. JobService.create() skips the "one active job per type" dedup in
-- Java for these; this widens 009c's exclusion so the database does not reject the concurrent
-- inserts either.
drop index uq_ingestion_job_active_type;

create unique index uq_ingestion_job_active_type
    on ingestion_job (type)
    where status in ('QUEUED', 'RUNNING') and type not in ('SBOM_UPLOAD', 'ASSET_SCAN', 'COMPLIANCE_SCAN');

--rollback drop index if exists uq_ingestion_job_active_type;
--rollback create unique index uq_ingestion_job_active_type on ingestion_job (type) where status in ('QUEUED', 'RUNNING') and type not in ('SBOM_UPLOAD', 'ASSET_SCAN');
