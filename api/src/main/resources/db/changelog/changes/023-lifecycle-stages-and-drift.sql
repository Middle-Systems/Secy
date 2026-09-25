--liquibase formatted sql

-- M1e -- SBOM lifecycle stages + diffing. See ROADMAP.md's "M1e -- SBOM lifecycle stages + diffing".
-- sbom.lifecycle_stage already exists (021c, nullable) and is now written at ingestion (explicit
-- ?stage= API param, else CycloneDX metadata.lifecycles). The active-SBOM slot becomes per
-- (product, lifecycle_stage) -- enforced in SBOMService, not here (the Unassigned bucket legitimately
-- holds many active SBOMs, and a partial index cannot see products.unassigned). Drift findings from
-- the three adjacent-stage diffs (Source->Build, Build->Deployed, Build->Analyzed) get their own
-- table; M1j folds them into its Finding supertype. No triage/severity columns -- M1j/M1i own those.
-- Enum-backed varchars are deliberately not value-checked here. No backfill: existing SBOMs keep
-- lifecycle_stage NULL ("unknown").

--changeset secy:023a-sbom-active-stage-index
--comment lookup index for the per-(product, lifecycle stage) active-SBOM slot
create index idx_sbom_product_stage_active on sbom (product_id, lifecycle_stage) where active = true;
--rollback drop index if exists idx_sbom_product_stage_active;

--changeset secy:023b-lifecycle-drift-finding
--comment one row per (product, adjacent stage pair, drift kind, component identity); reconciled, never deleted
create table lifecycle_drift_finding (
    id                    uuid          not null,
    tenant_id             uuid          not null,
    product_id            uuid          not null,
    stage_pair            varchar(32)   not null,
    drift_kind            varchar(32)   not null,
    identity_key          varchar(512)  not null,
    component_name        varchar(255),
    component_purl        varchar(512),
    observed_version      varchar(255),
    baseline_version      varchar(255),
    baseline_sbom_id      uuid          not null,
    observed_sbom_id      uuid          not null,
    observed_component_id uuid,
    summary               varchar(1024) not null,
    lifecycle_state       varchar(16)   not null,
    created_at            timestamp(6)  not null,
    last_seen_at          timestamp(6),
    constraint pk_lifecycle_drift_finding primary key (id),
    constraint fk_lifecycle_drift_finding_tenant foreign key (tenant_id) references tenant (id),
    constraint fk_lifecycle_drift_finding_product foreign key (product_id) references products (id) on delete cascade,
    constraint fk_lifecycle_drift_finding_baseline_sbom foreign key (baseline_sbom_id) references sbom (id) on delete cascade,
    constraint fk_lifecycle_drift_finding_observed_sbom foreign key (observed_sbom_id) references sbom (id) on delete cascade,
    constraint fk_lifecycle_drift_finding_observed_component foreign key (observed_component_id) references sbom_component (id) on delete set null,
    constraint uq_lifecycle_drift_finding_key unique (product_id, stage_pair, drift_kind, identity_key),
    constraint ck_lifecycle_drift_finding_identity_not_blank check (length(btrim(identity_key)) > 0)
);

create index idx_lifecycle_drift_finding_product_state on lifecycle_drift_finding (product_id, lifecycle_state);
create index idx_lifecycle_drift_finding_tenant on lifecycle_drift_finding (tenant_id);
create index idx_lifecycle_drift_finding_baseline_sbom on lifecycle_drift_finding (baseline_sbom_id);
create index idx_lifecycle_drift_finding_observed_sbom on lifecycle_drift_finding (observed_sbom_id);

--rollback drop table if exists lifecycle_drift_finding;
