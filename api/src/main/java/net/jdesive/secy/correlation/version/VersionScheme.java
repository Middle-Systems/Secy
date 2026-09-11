package net.jdesive.secy.correlation.version;

/**
 * How one ecosystem orders version strings.
 *
 * <p>"Is this component affected?" is, underneath, always the same question: does an ordering put
 * the component's version inside an interval the feed described. The ordering is the only part that
 * differs between npm and PyPI and Maven — so it is the only part that is pluggable. Both
 * correlation paths (OSV-primary and the NVD CPE fallback) call {@link #contains} against a
 * {@link VersionRange}; neither knows which scheme it got.
 *
 * <p>Implementations must be <b>total</b>: {@link #compare} never throws, whatever a feed or an SBOM
 * puts in a version field. An unparseable version degrades to a tolerant numeric/lexical comparison
 * rather than blowing up a scan — a correlation run that dies on one malformed PURL is worse than
 * one that mis-orders an exotic version.
 *
 * <p>Obtain one via {@link VersionSchemes#forEcosystem(String)}. Instances are stateless and
 * thread-safe.
 */
public interface VersionScheme {

    /** Stable identifier for logs and test assertions, e.g. {@code semver}, {@code pep440}. */
    String name();

    /**
     * Order two versions. Contract is {@link Comparable}'s: negative when {@code a} sorts before
     * {@code b}, zero when the two denote the same release, positive otherwise.
     *
     * <p>Zero means "the same release", not "the same string" — {@code 1.0} and {@code 1.0.0} are
     * equal under every scheme here.
     *
     * <p>Never throws. A {@code null} sorts below everything; two nulls are equal.
     */
    int compare(String a, String b);

    /** Convenience for {@code compare(a, b) == 0}. */
    default boolean sameVersion(String a, String b) {
        return compare(a, b) == 0;
    }

    /**
     * Whether {@code version} falls inside {@code range} under this scheme's ordering.
     *
     * <p>A {@code null} range means "no constraint" and matches; a {@code null} version matches
     * nothing, since an unversioned component cannot be shown to be affected.
     */
    default boolean contains(String version, VersionRange range) {
        if (version == null || version.isBlank()) {
            return false;
        }
        if (range == null) {
            return true;
        }
        if (range.lower() != null) {
            int c = compare(version, range.lower());
            if (c < 0 || (c == 0 && !range.lowerInclusive())) {
                return false;
            }
        }
        if (range.upper() != null) {
            int c = compare(version, range.upper());
            if (c > 0 || (c == 0 && !range.upperInclusive())) {
                return false;
            }
        }
        return true;
    }

    /**
     * The OSV event triple, evaluated directly.
     *
     * <p>Exists because that is the shape the OSV matcher has in hand; it is exactly
     * {@code contains(version, VersionRange.osv(introduced, fixed, lastAffected))}.
     *
     * @param version      the component's version
     * @param introduced   OSV {@code introduced} event (inclusive lower bound; {@code "0"} or null = unbounded)
     * @param fixed        OSV {@code fixed} event (exclusive upper bound), or null
     * @param lastAffected OSV {@code last_affected} event (inclusive upper bound), or null
     */
    default boolean inRange(String version, String introduced, String fixed, String lastAffected) {
        return contains(version, VersionRange.osv(introduced, fixed, lastAffected));
    }

    /**
     * The NVD {@code cpeMatch} attribute quartet, evaluated directly.
     *
     * <p>Exactly {@code contains(version, VersionRange.cpe(...))}.
     */
    default boolean inCpeRange(String version, String startIncluding, String startExcluding,
                               String endIncluding, String endExcluding) {
        return contains(version, VersionRange.cpe(startIncluding, startExcluding, endIncluding, endExcluding));
    }

}
