package net.jdesive.secy.persistence.entity;

/**
 * How firmly the correlation engine believes this alert's component really is the affected one.
 *
 * <p>Declaration order is strongest first, and code relies on it (see
 * {@code CorrelationService}'s de-duplication, which keeps the strongest match for a
 * {@code (component, CVE)} pair). <b>Do not reorder or insert values in the middle.</b>
 */
public enum MatchConfidence {

    /**
     * Ecosystem, package name <em>and</em> the exact version were all stated by the advisory. Only
     * the OSV path produces this, and only from an enumerated {@code versions[]} entry — the
     * advisory literally names the version the SBOM declares.
     */
    EXACT,

    /**
     * The package was identified unambiguously and its version fell inside a stated affected range.
     * OSV range hits and well-bounded NVD CPE rows both land here.
     */
    RANGE,

    /**
     * The package was identified by a name guess rather than a stated identity — a PURL type with no
     * CPE convention, a vendor we inferred, or a CPE row whose version field is a bare wildcard so
     * every version matches. Real often enough to show, weak enough to say so.
     */
    HEURISTIC

}
