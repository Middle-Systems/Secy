--liquibase formatted sql

-- Phase 3 — SBOM breadth (SPDX) + ingest hardening.
--
-- Gives a component a stable identity WITHIN ITS PRODUCT, independent of which SBOM version
-- introduced it. Phase 2's alert lifecycle (ACTIVE <-> AUTO_RESOLVED, "upsert, never duplicate")
-- was keyed on sbom_component.id, which is fresh on every upload — so a new SBOM for the same
-- product raised a second copy of every alert and never auto-resolved the first. CorrelationService
-- now keys on identity_key instead, scoped to the product.

--changeset secy:007a-sbom-component-identity-key
alter table sbom_component add column identity_key varchar(512);

create index idx_sbom_component_identity on sbom_component (identity_key);

-- Supports the product-scoped alert lookup (vulnerability_alert -> sbom_component -> sbom).
-- The FK exists from the baseline but Postgres does not index the referencing side automatically.
create index idx_sbom_component_sbom on sbom_component (sbom_id);

--rollback drop index if exists idx_sbom_component_sbom;
--rollback drop index if exists idx_sbom_component_identity;
--rollback alter table sbom_component drop column identity_key;

--changeset secy:007b-backfill-identity-key
-- Best-effort backfill so rows written before this column existed can still be carried forward.
--
-- This mirrors net.jdesive.secy.model.component.ComponentIdentity for the shapes that matter:
--   with a PURL    -> lowercased PURL with the trailing @version, ?qualifiers and #subpath removed,
--                     and the "pkg:" scheme dropped, e.g. pkg:npm/lodash@4.17.20 -> npm/lodash
--   without a PURL -> 'name/' || lower(name)
--
-- It is deliberately not a perfect reimplementation: percent-decoding (pkg:npm/%40angular/core ->
-- npm/@angular/core) and Maven's groupId:artifactId join are left to Java. Rows that differ simply
-- fail to carry forward once and are corrected on the product's next upload, when @PrePersist
-- recomputes the key from the same function correlation reads. Getting the common case right is
-- worth having; a stored procedure reproducing PackageURL parsing in SQL is not.
update sbom_component
set identity_key = case
    when purl is not null and purl <> '' then
        left(lower(regexp_replace(
            regexp_replace(
                regexp_replace(purl, '[#?].*$', ''),  -- drop subpath and qualifiers
                '@[^@/]*$', ''),                       -- drop the trailing @version
            '^pkg:', '')), 512)
    when name is not null and name <> '' then left('name/' || lower(name), 512)
    else null
end
where identity_key is null;

--rollback update sbom_component set identity_key = null;

--changeset secy:007c-widen-purl
-- Ingest hardening: 255 is short for a Go module PURL
-- (pkg:golang/github.com/<org>/<repo>/<subpackage>@v1.2.3) and for long Maven coordinates.
-- Matching SBOMComponent.purl @Column(length = 512).
alter table sbom_component alter column purl type varchar(512);

--rollback alter table sbom_component alter column purl type varchar(255);
