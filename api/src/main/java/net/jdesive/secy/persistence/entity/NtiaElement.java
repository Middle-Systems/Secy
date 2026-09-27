package net.jdesive.secy.persistence.entity;

/**
 * One of the seven NTIA "minimum elements" M1h scores an SBOM document against (ROADMAP.md —
 * "M1h — SBOM quality scoring"). Fixed declaration order — this is the order
 * {@link SbomQualityScore#getMissingElements()} reports gaps in.
 *
 * <p>The first five are per-component tests, averaged over the document's non-crypto,
 * root-excluded component population; the last two are document-level, all-or-nothing. See
 * {@code net.jdesive.secy.service.quality.SbomQualityScorer} for exactly how each is computed and
 * the equal-weight formula that combines them.
 */
public enum NtiaElement {
    SUPPLIER,
    COMPONENT_NAME,
    COMPONENT_VERSION,
    UNIQUE_IDENTIFIER,
    DEPENDENCY_RELATIONSHIP,
    AUTHOR,
    TIMESTAMP
}
