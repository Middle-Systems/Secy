--liquibase formatted sql

-- Phase 2 "correlation engine rework (OSV-primary)".
--
-- Three groups of change, one changeset each so a partial failure is legible:
--   006a  the OSV mirror (osv_advisory + its children + the per-ecosystem high-water mark)
--   006b  NVD cpeMatch version ranges, and the CVE List v5.1 / Vulnrichment fields on `vulnerabilities`
--   006c  match confidence and the alert lifecycle on `vulnerability_alert`
--
-- Mirrors net.jdesive.secy.persistence.entity.{OsvAdvisory, OsvAffectedRange, OsvEcosystemCursor,
-- CPEMatch, Vulnerability, VulnerabilityAlert}.

--changeset secy:006a-osv-mirror
--comment OSV mirror: advisories, affected ranges, aliases, enumerated versions, per-ecosystem cursor

-- One row per (OSV record x affected package). A record whose affected[] names several packages
-- fans out to several rows; record-level fields (aliases, summary, severity) are duplicated across
-- them so the correlation query needs no second hop. See OsvAdvisory's class javadoc.
create table osv_advisory (
    id uuid not null,
    osv_id varchar(255) not null,
    ecosystem varchar(64) not null,
    package_name varchar(512) not null,
    purl varchar(512),
    severity varchar(32),
    cvss_vector varchar(255),
    summary varchar(1024),
    details varchar(10024),
    references_json varchar(4096),
    modified timestamp(6),
    published timestamp(6),
    withdrawn timestamp(6),
    last_ingested_at timestamp(6),
    primary key (id)
);

-- The ingester's upsert key.
alter table osv_advisory
    add constraint uk_osv_advisory_record_package unique (osv_id, ecosystem, package_name);

-- The one hot query: OsvAdvisoryRepository.findForPackage, run once per SBOM component.
create index idx_osv_advisory_lookup on osv_advisory (ecosystem, package_name);
create index idx_osv_advisory_osv_id on osv_advisory (osv_id);

-- Record-level aliases (CVE-…, GHSA-…). A CVE alias is what resolves an advisory onto a
-- `vulnerabilities` row; without one the matcher skips the advisory.
create table osv_advisory_alias (
    advisory_id uuid not null,
    alias varchar(255) not null,
    primary key (advisory_id, alias)
);
create index idx_osv_advisory_alias_alias on osv_advisory_alias (alias);

-- The enumerated affected[].versions[] list some records carry instead of, or alongside, ranges.
create table osv_affected_version (
    advisory_id uuid not null,
    version varchar(255) not null,
    primary key (advisory_id, version)
);

-- One interval per row. OSV's ranges[] carry an ordered event list that can describe several
-- disjoint intervals; the ingester flattens each introduced->(fixed|last_affected) pair into its own
-- row. Correlation asks "is this version affected", which is a union over intervals either way.
create table osv_affected_range (
    id uuid not null,
    advisory_id uuid not null,
    range_type varchar(32),
    introduced varchar(255),
    fixed varchar(255),
    last_affected varchar(255),
    primary key (id)
);
create index idx_osv_affected_range_advisory on osv_affected_range (advisory_id);

alter table osv_advisory_alias
    add constraint fk_osv_advisory_alias_advisory foreign key (advisory_id) references osv_advisory (id);
alter table osv_affected_version
    add constraint fk_osv_affected_version_advisory foreign key (advisory_id) references osv_advisory (id);
alter table osv_affected_range
    add constraint fk_osv_affected_range_advisory foreign key (advisory_id) references osv_advisory (id);

-- Per-ecosystem high-water mark. OSV publishes one all.zip per ecosystem; the ingester records the
-- newest record `modified` it has written and skips anything not strictly newer next run.
create table osv_ecosystem_cursor (
    ecosystem varchar(64) not null,
    last_modified timestamp(6),
    last_ingested_at timestamp(6),
    primary key (ecosystem)
);

--rollback drop table if exists osv_ecosystem_cursor;
--rollback drop table if exists osv_affected_range;
--rollback drop table if exists osv_affected_version;
--rollback drop table if exists osv_advisory_alias;
--rollback drop table if exists osv_advisory;


--changeset secy:006b-cpe-ranges-and-cve5
--comment NVD cpeMatch version ranges; CVE List v5.1 status, CVSS source and SSVC decision points

-- The affected range NVD puts in configurations[].nodes[].cpeMatch[]. Without these the version
-- field inside `criteria` is a bare '*' on almost every modern row, and reading it as a version --
-- which is what correlation used to do -- matched every component against every CVE.
--
-- EXISTING ROWS STAY NULL UNTIL NVD IS RE-INGESTED (POST /nvd/ingest). A row with all four null and
-- a wildcard version still matches, at HEURISTIC confidence, so a stale database degrades to the old
-- behaviour rather than going silent.
alter table cpe_match add column version_start_including varchar(255);
alter table cpe_match add column version_start_excluding varchar(255);
alter table cpe_match add column version_end_including varchar(255);
alter table cpe_match add column version_end_excluding varchar(255);

-- CVE record lifecycle. PUBLISHED for every existing row: NVD only mirrors records the CVE Program
-- has published, so that is the truth for everything ingested so far. Only the CVE-List-v5 feed
-- moves a row off it, and REJECTED/DISPUTED rows are vetoed out of the actionable funnel.
alter table vulnerabilities add column cve_status varchar(16) not null default 'PUBLISHED';

-- Which container the CVSS score came from. Precedence NVD -> CNA -> ADP.
alter table vulnerabilities add column cvss_source varchar(32);

-- CISA-ADP SSVC decision points, stored as the raw lowercase tokens the ADP container publishes so a
-- new decision value needs no migration.
alter table vulnerabilities add column ssvc_exploitation varchar(32);
alter table vulnerabilities add column ssvc_automatable varchar(32);
alter table vulnerabilities add column ssvc_technical_impact varchar(32);

-- The funnel excludes REJECTED/DISPUTED, and the CVE browser flags them; both scan by status.
create index idx_vulnerabilities_cve_status on vulnerabilities (cve_status);

--rollback drop index if exists idx_vulnerabilities_cve_status;
--rollback alter table vulnerabilities drop column if exists ssvc_technical_impact;
--rollback alter table vulnerabilities drop column if exists ssvc_automatable;
--rollback alter table vulnerabilities drop column if exists ssvc_exploitation;
--rollback alter table vulnerabilities drop column if exists cvss_source;
--rollback alter table vulnerabilities drop column if exists cve_status;
--rollback alter table cpe_match drop column if exists version_end_excluding;
--rollback alter table cpe_match drop column if exists version_end_including;
--rollback alter table cpe_match drop column if exists version_start_excluding;
--rollback alter table cpe_match drop column if exists version_start_including;


--changeset secy:006c-alert-confidence-and-lifecycle
--comment Match confidence and the auto-resolve lifecycle on vulnerability_alert

-- EXACT / RANGE / HEURISTIC. Nullable: rows written before Phase 2 have no recorded provenance and
-- inventing one would be worse than admitting the gap. Every correlation path sets it from now on.
alter table vulnerability_alert add column match_confidence varchar(16);

-- ACTIVE / AUTO_RESOLVED. Correlation never deletes an alert: a match that no longer holds is
-- auto-resolved and kept, so the history survives and so does any triage a human had done to it.
-- NOT the Phase 7 triage state machine -- that records what a person decided and gets its own column.
alter table vulnerability_alert add column lifecycle_state varchar(16) not null default 'ACTIVE';

-- When correlation last confirmed the match. With created_at it bounds when an auto-resolved alert
-- stopped being reproducible, without a second timestamp column.
alter table vulnerability_alert add column last_seen_at timestamp(6);

-- GET /actionable now filters on `actionable AND lifecycle_state = 'ACTIVE'` and still orders by
-- EPSS descending. This index covers the new predicate; the 004 index it replaces would return
-- auto-resolved rows the query then discards.
create index idx_vuln_alert_active_epss
    on vulnerability_alert (epss_score desc nulls last)
    where actionable and lifecycle_state = 'ACTIVE';

drop index if exists idx_vuln_alert_actionable_epss;

--rollback create index idx_vuln_alert_actionable_epss on vulnerability_alert (epss_score desc nulls last) where actionable;
--rollback drop index if exists idx_vuln_alert_active_epss;
--rollback alter table vulnerability_alert drop column if exists last_seen_at;
--rollback alter table vulnerability_alert drop column if exists lifecycle_state;
--rollback alter table vulnerability_alert drop column if exists match_confidence;
