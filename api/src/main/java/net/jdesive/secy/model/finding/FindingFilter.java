package net.jdesive.secy.model.finding;

import net.jdesive.secy.persistence.entity.FindingType;

import java.util.Set;
import java.util.UUID;

/**
 * The {@code GET /findings} query string, parsed. Mirrors {@code ActionableFilter}'s "a filter that
 * only one arm can satisfy excludes the other arm entirely" discipline, generalized from two arms to
 * five.
 *
 * @param type            restrict to one arm. Null returns every arm {@link #linked}/scope allow.
 *                         {@code PROVENANCE} includes nothing — see {@link #includesVulnerability()}
 *                         and its siblings.
 * @param productId       only findings scoped to this product (vulnerability/compromise: via their
 *                         component's SBOM's product; the three plain-{@code productId} types:
 *                         directly).
 * @param assetId         only findings scoped to this asset (vulnerability/compromise only — the
 *                         three plain-{@code productId} types have no asset concept and are excluded
 *                         entirely when this is set, the same "filter only one arm can satisfy
 *                         excludes the other" rule).
 * @param includeResolved when false (the default), every arm restricts to {@code lifecycleState =
 *                         ACTIVE}; true also returns {@code AUTO_RESOLVED} rows.
 * @param linked          null: no restriction. {@code true}: only findings attached to an
 *                         {@code ActionItem}. {@code false}: only unattached findings.
 * @param productIds      M1k's {@code ownedBy} restriction — null: unrestricted. Non-null: only
 *                         findings scoped to one of these products (vulnerability/compromise via
 *                         their component's SBOM's product, the three plain-{@code productId} types
 *                         directly); asset-derived rows are always excluded, same reasoning as
 *                         {@link #assetId}'s interaction with the three plain-productId types. An
 *                         empty (non-null) set means "this user owns nothing" and must return
 *                         nothing — never "unfiltered".
 */
public record FindingFilter(
        FindingType type,
        UUID productId,
        UUID assetId,
        boolean includeResolved,
        Boolean linked,
        Set<UUID> productIds) {

    public boolean includesVulnerability() {
        return type == null || type == FindingType.VULNERABILITY;
    }

    public boolean includesCompromise() {
        return type == null || type == FindingType.COMPROMISE;
    }

    public boolean includesLifecycleDrift() {
        return (type == null || type == FindingType.LIFECYCLE_DRIFT) && assetId == null;
    }

    public boolean includesQuantumVulnerable() {
        return (type == null || type == FindingType.QUANTUM_VULNERABLE) && assetId == null;
    }

    public boolean includesSbomQuality() {
        return (type == null || type == FindingType.SBOM_QUALITY) && assetId == null;
    }

}
