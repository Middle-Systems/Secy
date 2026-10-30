--liquibase formatted sql

-- M1c -- Canonical component identity. See ROADMAP.md's "M1c -- Canonical component identity":
-- CPE and SWID become persisted secondary identifiers of an sbom_component instance (content hashes
-- already are, in sbom_component_hash from 011 -- deliberately not duplicated here). Identifiers that
-- disagree with the PURL-primary identity are flagged (identity_confidence = 'CONFLICTING' plus one
-- sbom_component_identity_conflict row per conflict), never merged: identity_key is unchanged.
-- Per-instance provenance is formalised on sbom: ingestion channel, source connector, and the M1e
-- lifecycle stage (nullable, unwritten until M1e -- present now so M1e needs no migration).
-- Enum-backed varchars are deliberately not value-checked here.

--changeset secy:021a-sbom-component-identifier
--comment declared CPE / SWID identifiers per sbom_component instance, with the document field each came from

create table sbom_component_identifier (
    id               uuid          not null,
    component_id     uuid          not null,
    identifier_type  varchar(16)   not null,
    identifier_value varchar(1024) not null,
    declared_name    varchar(255),
    declared_version varchar(255),
    source           varchar(64)   not null,
    constraint pk_sbom_component_identifier primary key (id),
    constraint fk_sbom_component_identifier_component foreign key (component_id) references sbom_component (id) on delete cascade,
    constraint uq_sbom_component_identifier unique (component_id, identifier_type, identifier_value),
    constraint ck_sbom_component_identifier_value_not_blank check (length(btrim(identifier_value)) > 0)
);

create index idx_sbom_component_identifier_value on sbom_component_identifier (identifier_type, identifier_value);

--rollback drop table if exists sbom_component_identifier;

--changeset secy:021b-sbom-component-identity-conflict
--comment identity-confidence flag on sbom_component plus one row per detected identifier conflict

alter table sbom_component add column identity_confidence varchar(16);

create table sbom_component_identity_conflict (
    id                 uuid          not null,
    component_id       uuid          not null,
    conflict_type      varchar(32)   not null,
    identifier_type    varchar(16)   not null,
    identifier_value   varchar(1024) not null,
    other_component_id uuid,
    other_identity_key varchar(512),
    detail             varchar(1024),
    detected_at        timestamp(6)  not null,
    constraint pk_sbom_component_identity_conflict primary key (id),
    constraint fk_sbom_component_identity_conflict_component foreign key (component_id) references sbom_component (id) on delete cascade,
    constraint ck_sbom_component_identity_conflict_other_pair check (num_nonnulls(other_component_id, other_identity_key) in (0, 2))
);

create index idx_sbom_component_identity_conflict_component on sbom_component_identity_conflict (component_id);

--rollback drop table if exists sbom_component_identity_conflict;
--rollback alter table sbom_component drop column identity_confidence;

--changeset secy:021c-sbom-provenance
--comment per-SBOM provenance: ingestion channel, originating source connector, and the (M1e) lifecycle stage

alter table sbom add column ingestion_source varchar(32);
alter table sbom add column source_connector_id uuid;
alter table sbom add column lifecycle_stage varchar(16);
alter table sbom add constraint fk_sbom_source_connector foreign key (source_connector_id) references source_connector (id) on delete set null;
create index idx_sbom_source_connector on sbom (source_connector_id) where source_connector_id is not null;

--rollback drop index if exists idx_sbom_source_connector;
--rollback alter table sbom drop constraint if exists fk_sbom_source_connector;
--rollback alter table sbom drop column lifecycle_stage;
--rollback alter table sbom drop column source_connector_id;
--rollback alter table sbom drop column ingestion_source;
