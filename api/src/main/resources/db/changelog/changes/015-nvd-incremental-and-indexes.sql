--liquibase formatted sql

-- NVD incremental ingest + the indexes the ingest write path and the dashboard/CPE-join queries
-- were missing.
--
-- 015a: nvd_ingest_cursor -- the same single-high-water-mark pattern osv_ecosystem_cursor (006a)
-- established, just one row instead of one per ecosystem: NVD is one global feed, not one per
-- package ecosystem. See net.jdesive.secy.persistence.entity.NvdIngestCursor and NVDService for how
-- it's read/advanced (a 119-day lastModStartDate/lastModEndDate sweep, cursor persisted after each
-- completed window so an interrupted run only has to redo its current window, not the whole feed).
--
-- 015b: indexes. `vulnerabilities.last_modified` is now on the ingest's own hot path (every
-- incremental run reads/writes near it) and was already being filtered on by
-- countByLastModifiedAfter/getIngestionTrend with no index backing it; `published` backs the same
-- two dashboard queries plus countBySeverityRecently. `cpe_operator.cve_id` and
-- `cpe_match.operator_id` back the join in findTopVulnerableProducts -- both were relying on a full
-- scan of tables that grow with every CVE ingested.

--changeset secy:015a-nvd-ingest-cursor
--comment NVD's high-water mark: one row, advanced after each completed date window

create table nvd_ingest_cursor (
    id varchar(32) not null,
    last_modified timestamp(6),
    last_ingested_at timestamp(6),
    primary key (id)
);

--rollback drop table if exists nvd_ingest_cursor;

--changeset secy:015b-ingest-indexes
--comment indexes for the NVD ingest write path and the CPE-join/dashboard read paths

create index idx_vulnerabilities_last_modified on vulnerabilities (last_modified);
create index idx_vulnerabilities_published on vulnerabilities (published);
create index idx_cpe_operator_cve_id on cpe_operator (cve_id);
create index idx_cpe_match_operator_id on cpe_match (operator_id);

--rollback drop index if exists idx_vulnerabilities_last_modified;
--rollback drop index if exists idx_vulnerabilities_published;
--rollback drop index if exists idx_cpe_operator_cve_id;
--rollback drop index if exists idx_cpe_match_operator_id;
