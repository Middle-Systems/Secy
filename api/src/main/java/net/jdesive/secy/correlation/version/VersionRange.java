package net.jdesive.secy.correlation.version;

/**
 * One contiguous interval of versions, expressed in the single shape both correlation paths can be
 * normalized into.
 *
 * <p>The two feeds describe "which versions are affected" very differently:
 *
 * <ul>
 *   <li><b>OSV</b> gives an ordered event list per range — {@code introduced}, then either
 *       {@code fixed} (the first <em>un</em>affected version, i.e. an <b>exclusive</b> upper bound)
 *       or {@code last_affected} (the last affected version, i.e. an <b>inclusive</b> upper
 *       bound).</li>
 *   <li><b>NVD CPE</b> gives four optional attributes on a {@code cpeMatch} row:
 *       {@code versionStartIncluding} / {@code versionStartExcluding} /
 *       {@code versionEndIncluding} / {@code versionEndExcluding}.</li>
 * </ul>
 *
 * <p>Both collapse to {@code (lower, lowerInclusive, upper, upperInclusive)} with {@code null}
 * meaning unbounded on that side, which is what {@link VersionScheme#contains} evaluates. Keeping
 * one shape is the point: the ecosystem-specific ordering lives in the scheme, never in the caller.
 *
 * @param lower          lower bound, or {@code null} for "from the beginning of time"
 * @param lowerInclusive whether a version equal to {@code lower} is inside the interval
 * @param upper          upper bound, or {@code null} for "and everything after"
 * @param upperInclusive whether a version equal to {@code upper} is inside the interval
 */
public record VersionRange(String lower, boolean lowerInclusive, String upper, boolean upperInclusive) {

    /** Every version. What an OSV range with only an {@code introduced: "0"} event means. */
    public static final VersionRange ALL = new VersionRange(null, true, null, false);

    /** Exactly one version — an enumerated OSV {@code versions[]} entry, or a concrete CPE version field. */
    public static VersionRange exact(String version) {
        return new VersionRange(version, true, version, true);
    }

    /**
     * An OSV affected range, flattened to one interval.
     *
     * <p>{@code introduced} is inclusive; OSV's literal {@code "0"} sentinel is treated as
     * unbounded so a scheme never has to decide whether {@code "0"} sorts below a pre-release.
     * {@code fixed} wins over {@code lastAffected} when a record carries both — the fixed version is
     * the harder statement, and it is the one that becomes the alert's fix version.
     */
    public static VersionRange osv(String introduced, String fixed, String lastAffected) {
        String lower = blank(introduced) || "0".equals(introduced.trim()) ? null : introduced.trim();
        if (!blank(fixed)) {
            return new VersionRange(lower, true, fixed.trim(), false);
        }
        if (!blank(lastAffected)) {
            return new VersionRange(lower, true, lastAffected.trim(), true);
        }
        return new VersionRange(lower, true, null, false);
    }

    /**
     * An NVD {@code cpeMatch} range.
     *
     * <p>NVD never emits both {@code Including} and {@code Excluding} on the same side; when a row
     * somehow carries both, the inclusive bound wins — the wider of the two, so a malformed row
     * errs toward reporting rather than silently dropping a real match.
     */
    public static VersionRange cpe(String startIncluding, String startExcluding,
                                   String endIncluding, String endExcluding) {
        String lower;
        boolean lowerInclusive;
        if (!blank(startIncluding)) {
            lower = startIncluding.trim();
            lowerInclusive = true;
        } else if (!blank(startExcluding)) {
            lower = startExcluding.trim();
            lowerInclusive = false;
        } else {
            lower = null;
            lowerInclusive = true;
        }

        String upper;
        boolean upperInclusive;
        if (!blank(endIncluding)) {
            upper = endIncluding.trim();
            upperInclusive = true;
        } else if (!blank(endExcluding)) {
            upper = endExcluding.trim();
            upperInclusive = false;
        } else {
            upper = null;
            upperInclusive = false;
        }

        return new VersionRange(lower, lowerInclusive, upper, upperInclusive);
    }

    /** True when nothing constrains this interval — it accepts every version. */
    public boolean isUnbounded() {
        return lower == null && upper == null;
    }

    /** True when the interval admits exactly one version. */
    public boolean isExact() {
        return lower != null && lower.equals(upper) && lowerInclusive && upperInclusive;
    }

    /**
     * True when nothing bounds the interval from above — an OSV range with no {@code fixed} and no
     * {@code last_affected}, which is how OSV says "still no published fix".
     */
    public boolean isOpenEnded() {
        return upper == null;
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }

}
