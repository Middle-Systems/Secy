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
 * {@code DockerVulnerabilityAlert} was the cautionary tale: it lived next to
 * {@code VulnerabilityAlert} since before Phase 1 and, having no join to {@code Vulnerability}, never
 * reached the funnel at all — it was still outside {@code GET /actionable} three phases later.
 * Duplicating the alert table duplicates the funnel, the enrichment, the dashboard roll-ups and the
 * {@code /actionable} query, and the roadmap's own design puts an asset finding in the <em>same</em>
 * list as a product finding. One alert table, two component parents.
 *
 * <p>Phase 5 closed that story: a CIS/Docker compliance report's vulnerability findings now become
 * {@code AssetComponent}s and ordinary {@code VulnerabilityAlert}s through this same interface, and
 * both dead Docker alert entities were deleted (migration {@code 010}).
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

    /**
     * <h2>Why component <em>hashes</em> are deliberately not on this interface</h2>
     *
     * <p>Phase 6 matches a component's SHA-256 against the malware-hash corpus, and the obvious move
     * was a fifth method here — one matcher, two parents, exactly like the four above.
     * {@code SBOMComponent} and {@code AssetComponent} do both carry a
     * {@link net.jdesive.secy.persistence.entity.ComponentHash} collection, so it would have
     * compiled. It is wrong, and the SBOM upload path proves it:
     *
     * <p>{@code VulnerabilityScanner.handleSbomUploaded} self-invokes its own
     * {@code @Transactional performAsyncScan}, so Spring's proxy never applies and the SBOM is loaded
     * outside a transaction. By the time {@code CorrelationService} is handed that graph it is
     * <b>detached</b>. The four methods above survive that because they are scalar columns already
     * materialised by the fetch join; a {@code FetchType.LAZY} collection reached through the same
     * interface throws {@code LazyInitializationException} instead. The four methods make a promise
     * about a <em>value</em>; a collection getter would be making one about a <em>session</em>, which
     * no interface can keep.
     *
     * <p>So {@code CompromiseDetectionService} loads digests by component id through the
     * repositories, inside its own transaction, and passes them down keyed by identity — the same
     * shape {@code CorrelationService} already uses for its scope-specific prior-alert queries. The
     * matcher below stays component-kind agnostic; only the loading step knows which table it is.
     *
     * @see net.jdesive.secy.persistence.SBOMComponentRepository#findHashesByComponentIds
     * @see net.jdesive.secy.persistence.AssetComponentRepository#findHashesByComponentIds
     */

}
