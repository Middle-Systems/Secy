--liquibase formatted sql

-- M1f -- VEX ingestion. See ROADMAP.md's "M1f -- VEX ingestion". OpenVEX, CSAF 2.0 (subset) and
-- CycloneDX VEX documents are parsed into vex_statement rows (never deleted; a superseded or
-- deactivated document's statements are flagged inactive). Each vulnerability_alert carries a
-- denormalized VEX resolution snapshot (vex_status / vex_justification / vex_statement_id /
-- vex_conflict), written only by VexResolutionService -- orthogonal to actionable and triage_state.
-- Per-tenant precedence policy in vex_precedence_config (default TENANT_OVER_VENDOR). Enum-backed
-- varchars are deliberately not value-checked, matching 019-023.

--changeset secy:024a-vex-precedence-config
--comment per-tenant VEX precedence policy, seeded with the default for every existing tenant
create table vex_precedence_config (
    id         uuid         not null,
    tenant_id  uuid         not null,
    policy     varchar(32)  not null,
    created_at timestamp(6) not null,
    updated_at timestamp(6) not null,
    constraint pk_vex_precedence_config primary key (id),
    constraint uq_vex_precedence_config_tenant unique (tenant_id),
    constraint fk_vex_precedence_config_tenant foreign key (tenant_id) references tenant (id)
);
-- 'TENANT_OVER_VENDOR' must equal VexPrecedenceConfig.DEFAULT_POLICY.
insert into vex_precedence_config (id, tenant_id, policy, created_at, updated_at)
select gen_random_uuid(), id, 'TENANT_OVER_VENDOR', now(), now() from tenant;
--rollback drop table if exists vex_precedence_config;

--changeset secy:024b-vex-document
--comment one row per uploaded VEX document; superseded/deactivated documents are kept, flagged inactive
create table vex_document (
    id                 uuid          not null,
    tenant_id          uuid          not null,
    format             varchar(16)   not null,
    spec_version       varchar(32),
    document_key       varchar(1024) not null,
    document_version   varchar(64),
    author             varchar(512),
    origin             varchar(16)   not null,
    scope_product_id   uuid,
    document_timestamp timestamp(6),
    status             varchar(16)   not null,
    job_id             uuid,
    pending_raw_body   text,
    content_sha256     varchar(64)   not null,
    active             boolean       not null,
    superseded_by_id   uuid,
    statement_count    integer       not null default 0,
    skipped_count      integer       not null default 0,
    warnings           varchar(4096),
    uploaded_at        timestamp(6)  not null,
    processed_at       timestamp(6),
    deactivated_at     timestamp(6),
    constraint pk_vex_document primary key (id),
    constraint fk_vex_document_tenant foreign key (tenant_id) references tenant (id),
    constraint fk_vex_document_scope_product foreign key (scope_product_id) references products (id) on delete cascade,
    constraint fk_vex_document_superseded_by foreign key (superseded_by_id) references vex_document (id) on delete set null,
    constraint ck_vex_document_key_not_blank check (length(btrim(document_key)) > 0)
);
create index idx_vex_document_job_id on vex_document (job_id);
create index idx_vex_document_tenant_uploaded on vex_document (tenant_id, uploaded_at);
create index idx_vex_document_supersession on vex_document (tenant_id, format, document_key) where active;
--rollback drop table if exists vex_document;

--changeset secy:024c-vex-statement
--comment one row per (document, CVE, target) VEX assertion; resolution reads only active rows
create table vex_statement (
    id                    uuid          not null,
    tenant_id             uuid          not null,
    document_id           uuid          not null,
    format                varchar(16)   not null,
    origin                varchar(16)   not null,
    scope_product_id      uuid,
    author                varchar(512),
    author_key            varchar(1024) not null,
    active                boolean       not null,
    cve_id                varchar(64)   not null,
    vulnerability_aliases varchar(1024),
    status                varchar(24)   not null,
    source_status         varchar(64)   not null,
    justification         varchar(64),
    source_justification  varchar(128),
    impact_statement      varchar(4096),
    action_statement      varchar(4096),
    product_ref           varchar(1024) not null,
    target_purl           varchar(1024),
    target_cpe            varchar(1024),
    match_key             varchar(512),
    match_version         varchar(255),
    statement_timestamp   timestamp(6)  not null,
    ordinal               integer       not null,
    created_at            timestamp(6)  not null,
    constraint pk_vex_statement primary key (id),
    constraint fk_vex_statement_tenant foreign key (tenant_id) references tenant (id),
    constraint fk_vex_statement_document foreign key (document_id) references vex_document (id) on delete cascade,
    constraint fk_vex_statement_scope_product foreign key (scope_product_id) references products (id) on delete cascade,
    constraint ck_vex_statement_cve_not_blank check (length(btrim(cve_id)) > 0)
);
create index idx_vex_statement_resolution on vex_statement (tenant_id, cve_id) where active;
create index idx_vex_statement_document on vex_statement (document_id);
--rollback drop table if exists vex_statement;

--changeset secy:024d-vulnerability-alert-vex-snapshot
--comment the VEX resolution snapshot on each alert; null/false = no VEX statement applies
alter table vulnerability_alert add column vex_status varchar(24);
alter table vulnerability_alert add column vex_justification varchar(64);
alter table vulnerability_alert add column vex_statement_id uuid;
alter table vulnerability_alert add column vex_conflict boolean not null default false;
alter table vulnerability_alert add column vex_updated_at timestamp(6);
alter table vulnerability_alert add constraint fk_vulnerability_alert_vex_statement
    foreign key (vex_statement_id) references vex_statement (id) on delete set null;
create index idx_vulnerability_alert_vex_status on vulnerability_alert (vex_status) where vex_status is not null;
--rollback drop index if exists idx_vulnerability_alert_vex_status;
--rollback alter table vulnerability_alert drop constraint if exists fk_vulnerability_alert_vex_statement;
--rollback alter table vulnerability_alert drop column vex_updated_at;
--rollback alter table vulnerability_alert drop column vex_conflict;
--rollback alter table vulnerability_alert drop column vex_statement_id;
--rollback alter table vulnerability_alert drop column vex_justification;
--rollback alter table vulnerability_alert drop column vex_status;

--changeset secy:024e-vex-upload-job-type
--comment VEX_UPLOAD joins the per-invocation job types excluded from the one-active-per-type index
drop index uq_ingestion_job_active_type;
create unique index uq_ingestion_job_active_type
    on ingestion_job (type)
    where status in ('QUEUED', 'RUNNING')
      and type not in ('SBOM_UPLOAD', 'ASSET_SCAN', 'COMPLIANCE_SCAN', 'CONNECTOR_SYNC', 'VEX_UPLOAD');
--rollback drop index if exists uq_ingestion_job_active_type;
--rollback create unique index uq_ingestion_job_active_type on ingestion_job (type) where status in ('QUEUED', 'RUNNING') and type not in ('SBOM_UPLOAD', 'ASSET_SCAN', 'COMPLIANCE_SCAN', 'CONNECTOR_SYNC');
