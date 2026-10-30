--liquibase formatted sql

-- M1l -- Dependency graph preserved. See ROADMAP.md's "M1l -- Dependency graph preserved". Each
-- ingested sbom_component gets an ingest-time classification (DIRECT / TRANSITIVE / UNKNOWN) from a
-- cycle-safe BFS over the document's directed dependency edges (CycloneDX dependencies[]; SPDX
-- DEPENDS_ON and the seven *_DEPENDENCY_OF types only), its hop distance from the product root, and
-- one representative shortest path (JSON array of bom-refs, root first). NULL depth = not assessed
-- (pre-M1l rows; no backfill -- raw bodies are cleared at ingest). The resolvable edges themselves
-- are kept in sbom_component_dependency so the M1d lineage graph (rebuilt from Postgres) can emit
-- DEPENDS_ON edges. Entities map the edge table with plain UUIDs (029b precedent); Postgres gets real
-- cascading FKs. Enum-backed varchars are deliberately not value-checked, matching 019-029.

--changeset secy:030a-sbom-component-dependency-position
--comment ingest-time direct/transitive classification, hop distance and one shortest path per sbom_component
alter table sbom_component add column dependency_depth varchar(16);
alter table sbom_component add column dependency_distance integer;
alter table sbom_component add column dependency_path text;
alter table sbom_component add constraint ck_sbom_component_dependency_distance_positive
    check (dependency_distance is null or dependency_distance >= 1);
--rollback alter table sbom_component drop constraint if exists ck_sbom_component_dependency_distance_positive;
--rollback alter table sbom_component drop column if exists dependency_path;
--rollback alter table sbom_component drop column if exists dependency_distance;
--rollback alter table sbom_component drop column if exists dependency_depth;

--changeset secy:030b-sbom-component-dependency
--comment declared directed dependency edges (component depends on depends_on_component) whose both ends resolved to a persisted sbom_component of the same SBOM, root row included
create table sbom_component_dependency (
    id                      uuid not null,
    sbom_id                 uuid not null,
    component_id            uuid not null,
    depends_on_component_id uuid not null,
    constraint pk_sbom_component_dependency primary key (id),
    constraint uq_sbom_component_dependency_edge unique (component_id, depends_on_component_id),
    constraint ck_sbom_component_dependency_no_self_loop check (component_id <> depends_on_component_id),
    constraint fk_sbom_component_dependency_sbom foreign key (sbom_id) references sbom (id) on delete cascade,
    constraint fk_sbom_component_dependency_component foreign key (component_id) references sbom_component (id) on delete cascade,
    constraint fk_sbom_component_dependency_depends_on foreign key (depends_on_component_id) references sbom_component (id) on delete cascade
);
create index idx_sbom_component_dependency_sbom on sbom_component_dependency (sbom_id);
create index idx_sbom_component_dependency_depends_on on sbom_component_dependency (depends_on_component_id);
--rollback drop table if exists sbom_component_dependency;
