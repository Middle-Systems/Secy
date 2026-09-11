--liquibase formatted sql

-- Phase 4 — Infrastructure / asset inventory (ROADMAP.md).
--
-- The architecture decision this phase could no longer defer: vulnerability_alert.component_id was
-- an sbom_component FK, and a container-image or filesystem scan has no SBOM at all. The alert's
-- component reference is widened here to TWO nullable FKs with an XOR check, rather than to a JPA
-- inheritance hierarchy over a shared Component entity:
--
--   * single-table inheritance would need a discriminator on sbom_component and would make every
--     existing SBOMComponent query polymorphic;
--   * joined inheritance would move the id into a parent table and break every FK already pointing
--     at sbom_component (vulnerability_alert, sbom_license, sbom_reference, sbom.component_id);
--   * a parallel asset_vulnerability_alert table would duplicate the funnel, the enrichment and the
--     /actionable query -- which is exactly how docker_vulnerabitity_alert ended up outside the
--     funnel entirely.
--
-- Two nullable FKs cost one check constraint and change nothing that already works.
--
-- Correlation identity: asset_component.identity_key is the SAME version-less-PURL spelling
-- sbom_component.identity_key uses (see 007), so "maven/org.apache.logging.log4j:log4j-core" means
-- one thing estate-wide. The SCOPE it reconciles within differs -- product for SBOM components,
-- asset for asset components -- because an asset need not belong to a product, and because sharing
-- the scope would let an image re-scan auto-resolve alerts raised by a product's SBOM.

--changeset secy:009a-asset-inventory
create table asset (
    id uuid not null,
    type varchar(32) not null,
    name varchar(512) not null,
    product_id uuid,
    last_scanned_at timestamp(6),
    status varchar(32),
    scanner varchar(32),
    pending_raw_body text,
    pending_scan_format varchar(16),
    job_id uuid,
    created_at timestamp(6) not null,
    primary key (id)
);

-- The upsert key for a scan: re-scanning acme/api:1.4.2 must land on the row that already holds its
-- components and alerts, or every scan raises a fresh copy of every alert.
alter table asset add constraint uq_asset_type_name unique (type, name);

alter table asset add constraint fk_asset_product foreign key (product_id) references products (id);

create index idx_asset_product on asset (product_id);
create index idx_asset_job_id on asset (job_id);

create table asset_declared_cpe (
    asset_id uuid not null,
    cpe varchar(512)
);

alter table asset_declared_cpe add constraint fk_asset_declared_cpe_asset
    foreign key (asset_id) references asset (id);

create index idx_asset_declared_cpe_asset on asset_declared_cpe (asset_id);

create table asset_component (
    id uuid not null,
    asset_id uuid not null,
    name varchar(512),
    version varchar(255),
    purl varchar(512),
    ecosystem varchar(64),
    identity_key varchar(512),
    source varchar(16),
    scan_target varchar(512),
    package_path varchar(1024),
    layer varchar(255),
    present_in_last_scan boolean not null default true,
    last_seen_at timestamp(6),
    primary key (id)
);

alter table asset_component add constraint fk_asset_component_asset
    foreign key (asset_id) references asset (id);

-- One row per package identity per asset. This is what makes the scan an upsert rather than a
-- replace, which in turn is what keeps the alerts citing those rows valid across a re-scan.
alter table asset_component add constraint uq_asset_component_identity unique (asset_id, identity_key);

create index idx_asset_component_asset on asset_component (asset_id);
create index idx_asset_component_identity on asset_component (identity_key);

--rollback drop table if exists asset_component;
--rollback drop table if exists asset_declared_cpe;
--rollback drop table if exists asset;

--changeset secy:009b-alert-asset-component
alter table vulnerability_alert add column asset_component_id uuid;

alter table vulnerability_alert add constraint fk_vuln_alert_asset_component
    foreign key (asset_component_id) references asset_component (id);

create index idx_vuln_alert_asset_component on vulnerability_alert (asset_component_id);

-- The XOR that makes the two FKs a single polymorphic reference rather than two independent ones.
-- An alert describes exactly one component, observed in exactly one place; a row with both set would
-- make "which estate is this finding in" unanswerable, and a row with neither has never been
-- producible (every correlation path attaches a component before saving).
alter table vulnerability_alert add constraint ck_vuln_alert_one_component
    check (num_nonnulls(component_id, asset_component_id) = 1);

--rollback alter table vulnerability_alert drop constraint if exists ck_vuln_alert_one_component;
--rollback drop index if exists idx_vuln_alert_asset_component;
--rollback alter table vulnerability_alert drop constraint if exists fk_vuln_alert_asset_component;
--rollback alter table vulnerability_alert drop column asset_component_id;

--changeset secy:009c-asset-scan-job-type
-- ASSET_SCAN joins SBOM_UPLOAD as a per-invocation job type: each scan is its own unit of work with
-- its own payload (which asset row to finish ingesting), so several may be QUEUED/RUNNING at once.
-- JobService.create() skips the "one active job per type" dedup in Java for these; this widens 008b's
-- exclusion so the database does not reject the concurrent inserts either.
drop index uq_ingestion_job_active_type;

create unique index uq_ingestion_job_active_type
    on ingestion_job (type)
    where status in ('QUEUED', 'RUNNING') and type not in ('SBOM_UPLOAD', 'ASSET_SCAN');

--rollback drop index if exists uq_ingestion_job_active_type;
--rollback create unique index uq_ingestion_job_active_type on ingestion_job (type) where status in ('QUEUED', 'RUNNING') and type <> 'SBOM_UPLOAD';
