--liquibase formatted sql

-- Phase 6b — Source & cloud connectors, GitHub first, agentless (ROADMAP.md).
--
-- SourceConnector holds "where to look", never a credential: the GitHub token is a single
-- instance-wide env var (SECY_GITHUB_TOKEN), read by GitHubApiClient the same way NVDService reads
-- nvd.apikey, so there is nothing secret to persist here. type is varchar(16) because GITHUB is
-- (deliberately) the only value for this pass -- see SourceConnectorType.
--
-- ingestion_job.type does NOT need widening: it has been varchar(32) since migration 011e (to fit
-- MALICIOUS_PACKAGES, 18 characters), and CONNECTOR_SYNC is 14.

--changeset secy:013a-source-connector
create table source_connector (
    id             uuid not null,
    type           varchar(16)  not null,
    name           varchar(255) not null,
    scope          varchar(255) not null,
    status         varchar(32),
    last_synced_at timestamp(6),
    job_id         uuid,
    created_at     timestamp(6) not null,
    primary key (id)
);

-- GitHubSyncService looks a connector up by the job currently syncing it, same pattern as
-- sbom.job_id / asset.job_id / docker_compliance_report.job_id.
create index idx_source_connector_job_id on source_connector (job_id);

create table source_connector_repo_allowlist (
    connector_id    uuid not null,
    repo_full_name  varchar(255)
);

alter table source_connector_repo_allowlist add constraint fk_source_connector_repo_allowlist_connector
    foreign key (connector_id) references source_connector (id);

create index idx_source_connector_repo_allowlist_connector on source_connector_repo_allowlist (connector_id);

--rollback drop table if exists source_connector_repo_allowlist;
--rollback drop index if exists idx_source_connector_job_id;
--rollback drop table if exists source_connector;

--changeset secy:013b-connector-sync-job-type
-- CONNECTOR_SYNC joins SBOM_UPLOAD, ASSET_SCAN and COMPLIANCE_SCAN as a per-invocation job type:
-- each connector's sync is its own unit of work with its own payload (which source_connector row to
-- finish syncing), so several connectors may sync concurrently. JobService.create() skips the "one
-- active job per type" dedup in Java for this type; this widens 010f's exclusion so the database
-- does not reject the concurrent inserts either.
drop index uq_ingestion_job_active_type;

create unique index uq_ingestion_job_active_type
    on ingestion_job (type)
    where status in ('QUEUED', 'RUNNING')
      and type not in ('SBOM_UPLOAD', 'ASSET_SCAN', 'COMPLIANCE_SCAN', 'CONNECTOR_SYNC');

--rollback drop index if exists uq_ingestion_job_active_type;
--rollback create unique index uq_ingestion_job_active_type on ingestion_job (type) where status in ('QUEUED', 'RUNNING') and type not in ('SBOM_UPLOAD', 'ASSET_SCAN', 'COMPLIANCE_SCAN');
