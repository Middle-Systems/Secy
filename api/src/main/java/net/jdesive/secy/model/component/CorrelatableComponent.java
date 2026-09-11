package net.jdesive.secy.model.component;

/**
 * "A thing Secy can look up in a vulnerability corpus", regardless of where it was observed.
 *
 * <h2>Why this exists (the Phase 4 architecture decision)</h2>
 *
 * <p>Phase 2 flagged it and Phase 3 deferred it: {@code VulnerabilityAlert.component} was an
 * {@code SBOMComponent} FK, and an SBOM is the only place a component could come from. Phase 4
 * breaks that assumption — a container-image or filesystem scan has no {@code SBOM} at all, so the
 * alert's component reference had to widen.
 *
 * <p>The widening is a <b>plain Java interface plus two nullable FKs</b>, not a JPA inheritance
 * hierarchy:
 *
 * <ul>
 *   <li>{@code SBOMComponent} and {@link net.jdesive.secy.persistence.entity.AssetComponent} both
 *       implement this. Nothing about their tables, ids or existing queries changes.</li>
 *   <li>{@code VulnerabilityAlert} carries {@code component} (SBOM-derived) and
 *       {@code assetComponent} (asset-derived) with an XOR invariant — exactly one is non-null,
 *       enforced by the setters in Java and by a {@code check} constraint in migration {@code 009}.</li>
 * </ul>
 *
 * <p><b>Why not single-table or joined inheritance over a shared {@code Component} entity.</b>
 * Either would have rewritten {@code sbom_component}: single-table needs a discriminator column and
 * makes every existing {@code SBOMComponent} query polymorphic; joined inheritance moves the id into
 * a parent table and breaks every FK that already points at it. Both would have churned the whole of
 * Phase 1-3 — {@code CorrelationService}, {@code EnrichmentService}, the repositories, the alert
 * JSON — for no behaviour Secy needs. The one thing correlation actually wants from a component is
 * the four fields below, and an interface supplies them at zero schema cost.
 *
 * <p><b>Why not a parallel {@code AssetVulnerabilityAlert} table (option B).</b> Because
 * {@code DockerVulnerabilityAlert} is the cautionary tale: it has lived next to
 * {@code VulnerabilityAlert} since before Phase 1 and, having no join to {@code Vulnerability}, has
 * never reached the funnel at all — it is still outside {@code GET /actionable} three phases later.
 * Duplicating the alert table duplicates the funnel, the enrichment, the dashboard roll-ups and the
 * {@code /actionable} query, and the roadmap's own design puts an asset finding in the <em>same</em>
 * list as a product finding. One alert table, two component parents.
 */
public interface CorrelatableComponent {

    /** Ecosystem-native package name, or whatever the document/scanner called it. */
    String getName();

    /** The observed version, or null. */
    String getVersion();

    /** Package URL, or null when none could be determined. */
    String getPurl();

    /**
     * The stable identity correlation keys its alert upsert on.
     *
     * <p>Same spelling for both implementations — {@link ComponentIdentity#keyOf} — so
     * {@code maven/org.apache.logging.log4j:log4j-core} means the same string whether it was read out
     * of an SBOM or off a scanned image. The <em>scope</em> the key is reconciled within differs
     * (product for SBOM components, asset for asset components); see {@code CorrelationService}.
     */
    String getIdentityKey();

}
