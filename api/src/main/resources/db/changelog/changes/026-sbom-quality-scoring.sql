--liquibase formatted sql

-- M1h -- SBOM quality scoring. See ROADMAP.md's "M1h -- SBOM quality scoring". Each ingested SBOM is
-- scored 0-100 against the NTIA minimum elements (supplier, name, version, unique identifier,
-- dependency relationship -- per-component coverage; author, timestamp -- document-level), stored on
-- sbom as quality_* columns (null = not scored: no non-crypto components). Supplier, document author
-- and document timestamp become first-class parsed fields. A score below the threshold becomes an
-- sbom_quality_finding row per (product, lifecycle-stage slot) -- or per SBOM for the Unassigned
-- bucket -- reconciled like quantum_vulnerability_finding (never deleted, no triage/severity --
-- M1j/M1i own those). Dependency relationship is PRESENCE-only (M1l owns the real graph). No backfill:
-- pre-M1h SBOMs keep every new column NULL. Enum-backed varchars are deliberately not value-checked,
-- matching 019-025.

--changeset secy:026a-sbom-component-supplier
--comment NTIA supplier name per component instance (CycloneDX component.supplier.name / SPDX PackageSupplier)
alter table sbom_component add column supplier_name varchar(255);
--rollback alter table sbom_component drop column supplier_name;

--changeset secy:026b-sbom-document-metadata-and-quality
--comment document-declared creation timestamp and SBOM-data authors, plus the NTIA minimum-elements quality score and breakdown
alter table sbom add column document_timestamp timestamp(6);
alter table sbom add column document_authors varchar(1024);
alter table sbom add column quality_score integer;
alter table sbom add column quality_supplier_pct integer;
alter table sbom add column quality_name_pct integer;
alter table sbom add column quality_version_pct integer;
alter table sbom add column quality_unique_id_pct integer;
alter table sbom add column quality_dependency_pct integer;
alter table sbom add column quality_has_author boolean;
alter table sbom add column quality_has_timestamp boolean;
alter table sbom add column quality_components_scored integer;
alter table sbom add constraint ck_sbom_quality_score_range check (quality_score is null or (quality_score between 0 and 100));
--rollback alter table sbom drop constraint if exists ck_sbom_quality_score_range;
--rollback alter table sbom drop column quality_components_scored;
--rollback alter table sbom drop column quality_has_timestamp;
--rollback alter table sbom drop column quality_has_author;
--rollback alter table sbom drop column quality_dependency_pct;
--rollback alter table sbom drop column quality_unique_id_pct;
--rollback alter table sbom drop column quality_version_pct;
--rollback alter table sbom drop column quality_name_pct;
--rollback alter table sbom drop column quality_supplier_pct;
--rollback alter table sbom drop column quality_score;
--rollback alter table sbom drop column document_authors;
--rollback alter table sbom drop column document_timestamp;

--changeset secy:026c-sbom-quality-finding
--comment one row per (product, lifecycle-stage slot) -- or per Unassigned-bucket SBOM -- whose current SBOM scores below the NTIA quality threshold; reconciled, never deleted
create table sbom_quality_finding (
    id                         uuid          not null,
    tenant_id                  uuid          not null,
    product_id                 uuid          not null,
    scope_sbom_id              uuid,
    lifecycle_stage            varchar(16),
    sbom_id                    uuid          not null,
    quality_score              integer       not null,
    quality_supplier_pct       integer       not null,
    quality_name_pct           integer       not null,
    quality_version_pct        integer       not null,
    quality_unique_id_pct      integer       not null,
    quality_dependency_pct     integer       not null,
    quality_has_author         boolean       not null,
    quality_has_timestamp      boolean       not null,
    quality_components_scored  integer       not null,
    score_threshold            integer       not null,
    missing_elements           varchar(255)  not null,
    summary                    varchar(1024) not null,
    lifecycle_state            varchar(16)   not null,
    created_at                 timestamp(6)  not null,
    last_seen_at               timestamp(6),
    constraint pk_sbom_quality_finding primary key (id),
    constraint fk_sbom_quality_finding_tenant foreign key (tenant_id) references tenant (id),
    constraint fk_sbom_quality_finding_product foreign key (product_id) references products (id) on delete cascade,
    constraint fk_sbom_quality_finding_scope_sbom foreign key (scope_sbom_id) references sbom (id) on delete cascade,
    constraint fk_sbom_quality_finding_sbom foreign key (sbom_id) references sbom (id) on delete cascade,
    constraint ck_sbom_quality_finding_score_range check (quality_score between 0 and 100)
);
create unique index uq_sbom_quality_finding_product_slot
    on sbom_quality_finding (product_id, coalesce(lifecycle_stage, 'UNSTAGED')) where scope_sbom_id is null;
create unique index uq_sbom_quality_finding_scope_sbom
    on sbom_quality_finding (scope_sbom_id) where scope_sbom_id is not null;
create index idx_sbom_quality_finding_product_state on sbom_quality_finding (product_id, lifecycle_state);
create index idx_sbom_quality_finding_tenant on sbom_quality_finding (tenant_id);
create index idx_sbom_quality_finding_sbom on sbom_quality_finding (sbom_id);
--rollback drop table if exists sbom_quality_finding;
