package net.jdesive.secy.correlation;

import net.jdesive.secy.persistence.entity.FixSource;
import net.jdesive.secy.persistence.entity.FixState;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * What correlation learned about whether a fix exists — the three alert columns
 * ({@code fixState}, {@code fixedVersions}, {@code fixSource}) travelling together so they cannot
 * be set inconsistently.
 *
 * @param state    FIXED / NO_FIX / UNKNOWN
 * @param versions comma-joined fixed version(s), non-null exactly when {@code state} is FIXED
 * @param source   which corpus said so — {@link FixSource#OSV} is authoritative,
 *                 {@link FixSource#CPE_RANGE} is an inference and is flagged as such in the UI
 */
public record FixResolution(FixState state, String versions, FixSource source) {

    /** A fix exists at these versions. */
    public static FixResolution fixed(Collection<String> versions, FixSource source) {
        Set<String> distinct = new LinkedHashSet<>();
        for (String version : versions) {
            if (version != null && !version.isBlank()) {
                distinct.add(version.trim());
            }
        }
        if (distinct.isEmpty()) {
            return unknown(source);
        }
        return new FixResolution(FixState.FIXED, String.join(", ", distinct), source);
    }

    /** A fix exists at this version. */
    public static FixResolution fixed(String version, FixSource source) {
        return fixed(Set.of(version), source);
    }

    /**
     * The advisory bounds the affected versions from below and never closes them — the feed is
     * saying, positively, that no fixed release has been published.
     */
    public static FixResolution noFix(FixSource source) {
        return new FixResolution(FixState.NO_FIX, null, source);
    }

    /** The source has nothing to say about a fix. Distinct from {@link #noFix}, which is a claim. */
    public static FixResolution unknown(FixSource source) {
        return new FixResolution(FixState.UNKNOWN, null, source);
    }

    /** True when this resolution actually names a fixed version. */
    public boolean isFixed() {
        return state == FixState.FIXED && versions != null;
    }

    /**
     * The more useful of two resolutions for the same alert: a named fix beats a {@code NO_FIX}
     * claim, which beats {@code UNKNOWN}. Ties keep the first.
     */
    public static FixResolution best(FixResolution a, FixResolution b) {
        if (a == null) {
            return b;
        }
        if (b == null) {
            return a;
        }
        return rank(a) >= rank(b) ? a : b;
    }

    private static int rank(FixResolution resolution) {
        return switch (resolution.state()) {
            case FIXED -> 2;
            case NO_FIX -> 1;
            case UNKNOWN -> 0;
        };
    }

}
