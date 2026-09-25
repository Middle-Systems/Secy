package net.jdesive.secy.persistence.entity;

/**
 * How well an {@code sbom_component}'s own declared secondary identifiers (CPE, SWID, content hash)
 * agree with its PURL-primary {@link SBOMComponent#getIdentityKey() identity} and with each other
 * (M1c, ROADMAP.md — "Canonical component identity").
 *
 * <p><b>This is orthogonal to {@link MatchConfidence} — do not conflate the two.</b>
 * {@code MatchConfidence} is a per-{@code (component, CVE)} <em>alert</em> value: how firmly a
 * specific vulnerability match was identified, computed at correlation time and dependent on which
 * CVE is in question. {@code IdentityConfidence} is a per-component-<em>instance</em>, CVE-independent
 * judgment computed once at ingestion from the document's own facts — it exists before, and without,
 * any CVE. M1c does not cap or otherwise influence {@code MatchConfidence}; a later phase (M1i) may
 * use this as one scoring input, but nothing here changes how an alert's own confidence is decided.
 *
 * <ul>
 *   <li>{@link #CORROBORATED} — at least one declared CPE or SWID agrees with the primary identity
 *       (name-token overlap, and version agreement when both state a concrete version), and nothing
 *       disagrees.</li>
 *   <li>{@link #UNCORROBORATED} — no secondary identifier was declared at all, or none of them speak
 *       to the primary identity either way (e.g. hash-only, or a CPE 2.2 URI, which is stored but not
 *       assessed).</li>
 *   <li>{@link #CONFLICTING} — this is the roadmap's "low-confidence" flag: at least one declared
 *       identifier disagrees with the primary identity, or the same strong content digest was found
 *       on a component with a different {@code identityKey} elsewhere in the tenant.</li>
 * </ul>
 *
 * <p>{@code null} on {@link SBOMComponent#getIdentityConfidence()} means "not assessed" (e.g. a
 * component built directly rather than through the normal ingest path, such as the correlation
 * golden-set fixtures) — never treat null as any of the three values above.
 *
 * <p>No code may rely on this enum's declaration order (contrast {@link MatchConfidence}, whose
 * order is load-bearing).
 *
 * <p>M1i consumes {@code identity_confidence} as a scoring input; M1c does not cap
 * {@code MatchConfidence} with it.
 */
public enum IdentityConfidence {
    CORROBORATED,
    UNCORROBORATED,
    CONFLICTING
}
