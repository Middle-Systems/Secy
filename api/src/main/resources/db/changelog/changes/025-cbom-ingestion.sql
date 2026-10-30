--liquibase formatted sql

-- M1g -- CBOM ingestion. See ROADMAP.md's "M1g -- CBOM ingestion". CycloneDX >= 1.6 components of
-- type cryptographic-asset get one sbom_component_crypto_asset row (cryptoProperties subset +
-- sanitized raw JSON; relatedCryptoMaterialProperties.value is never stored) carrying an
-- ingest-time Shor-vulnerability classification. Assets classified VULNERABLE become
-- quantum_vulnerability_finding rows, reconciled like lifecycle_drift_finding (never deleted, no
-- triage/severity -- M1j/M1i own those). Enum-backed varchars are deliberately not value-checked,
-- matching 019-024.

--changeset secy:025a-sbom-component-crypto-asset
--comment CycloneDX 1.6 cryptoProperties per cryptographic-asset sbom_component (1:1), with its quantum classification
create table sbom_component_crypto_asset (
    id                          uuid          not null,
    component_id                uuid          not null,
    asset_type                  varchar(32)   not null,
    declared_asset_type         varchar(64),
    oid                         varchar(255),
    crypto_identity_key         varchar(512),
    primitive                   varchar(32),
    parameter_set_identifier    varchar(128),
    curve                       varchar(128),
    execution_environment       varchar(64),
    implementation_platform     varchar(64),
    certification_levels        varchar(512),
    algorithm_mode              varchar(32),
    padding                     varchar(32),
    crypto_functions            varchar(512),
    classical_security_level    integer,
    nist_quantum_security_level integer,
    subject_name                varchar(1024),
    issuer_name                 varchar(1024),
    not_valid_before            timestamp(6),
    not_valid_after             timestamp(6),
    signature_algorithm_ref     varchar(255),
    subject_public_key_ref      varchar(255),
    certificate_format          varchar(64),
    certificate_extension       varchar(64),
    material_type               varchar(32),
    material_id                 varchar(255),
    material_state              varchar(32),
    algorithm_ref               varchar(255),
    material_creation_date      timestamp(6),
    material_activation_date    timestamp(6),
    material_update_date        timestamp(6),
    material_expiration_date    timestamp(6),
    material_size               integer,
    material_format              varchar(64),
    secured_by_mechanism        varchar(64),
    secured_by_algorithm_ref    varchar(255),
    protocol_type               varchar(32),
    protocol_version            varchar(64),
    cipher_suites               varchar(4096),
    crypto_refs                 varchar(2048),
    quantum_status              varchar(16)   not null,
    quantum_family              varchar(32),
    quantum_basis               varchar(32),
    quantum_indicator           varchar(255),
    crypto_properties_json      text,
    constraint pk_sbom_component_crypto_asset primary key (id),
    constraint fk_sbom_component_crypto_asset_component foreign key (component_id) references sbom_component (id) on delete cascade,
    constraint uq_sbom_component_crypto_asset_component unique (component_id)
);
--rollback drop table if exists sbom_component_crypto_asset;

--changeset secy:025b-quantum-vulnerability-finding
--comment one row per (product | bucket SBOM, crypto asset identity) classified Shor-vulnerable; reconciled, never deleted
create table quantum_vulnerability_finding (
    id                          uuid          not null,
    tenant_id                   uuid          not null,
    product_id                  uuid          not null,
    scope_sbom_id               uuid,
    crypto_identity_key         varchar(512)  not null,
    asset_type                  varchar(32)   not null,
    algorithm_family            varchar(32)   not null,
    classification_basis        varchar(32)   not null,
    matched_indicator           varchar(255),
    declared_nist_quantum_level integer,
    component_name              varchar(255),
    bom_ref                     varchar(255),
    sbom_id                     uuid          not null,
    component_id                uuid,
    crypto_asset_id             uuid,
    summary                     varchar(1024) not null,
    lifecycle_state             varchar(16)   not null,
    created_at                  timestamp(6)  not null,
    last_seen_at                timestamp(6),
    constraint pk_quantum_vulnerability_finding primary key (id),
    constraint fk_quantum_vulnerability_finding_tenant foreign key (tenant_id) references tenant (id),
    constraint fk_quantum_vulnerability_finding_product foreign key (product_id) references products (id) on delete cascade,
    constraint fk_quantum_vulnerability_finding_scope_sbom foreign key (scope_sbom_id) references sbom (id) on delete cascade,
    constraint fk_quantum_vulnerability_finding_sbom foreign key (sbom_id) references sbom (id) on delete cascade,
    constraint fk_quantum_vulnerability_finding_component foreign key (component_id) references sbom_component (id) on delete set null,
    constraint fk_quantum_vulnerability_finding_crypto_asset foreign key (crypto_asset_id) references sbom_component_crypto_asset (id) on delete set null,
    constraint ck_quantum_vulnerability_finding_identity_not_blank check (length(btrim(crypto_identity_key)) > 0)
);
create unique index uq_quantum_vulnerability_finding_product_key
    on quantum_vulnerability_finding (product_id, crypto_identity_key) where scope_sbom_id is null;
create unique index uq_quantum_vulnerability_finding_scope_sbom_key
    on quantum_vulnerability_finding (scope_sbom_id, crypto_identity_key) where scope_sbom_id is not null;
create index idx_quantum_vulnerability_finding_product_state on quantum_vulnerability_finding (product_id, lifecycle_state);
create index idx_quantum_vulnerability_finding_tenant on quantum_vulnerability_finding (tenant_id);
create index idx_quantum_vulnerability_finding_sbom on quantum_vulnerability_finding (sbom_id);
--rollback drop table if exists quantum_vulnerability_finding;
