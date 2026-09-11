package net.jdesive.secy.correlation.version;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Semantic Versioning 2.0.0 ordering, with the tolerance real SBOMs demand.
 *
 * <p>Serves npm, crates.io, NuGet, RubyGems, Hex, Packagist and Pub — every ecosystem whose
 * versions are "dotted numbers, optionally a pre-release, optionally build metadata". Strict SemVer
 * rules apply where the input is strict SemVer:
 *
 * <ul>
 *   <li>release components compare numerically, left to right;</li>
 *   <li>a pre-release sorts <b>below</b> the same release without one ({@code 1.0.0-rc1 < 1.0.0});</li>
 *   <li>pre-release identifiers compare dot-by-dot: numeric ones numerically, numeric below
 *       alphanumeric, alphanumeric ASCII-lexically, and a shorter prefix below a longer one;</li>
 *   <li>build metadata after {@code +} is ignored entirely, per the spec.</li>
 * </ul>
 *
 * <p>Three tolerances beyond the spec, each earned by a real corpus:
 *
 * <ol>
 *   <li><b>Missing components.</b> {@code 1.0} and {@code 1} are read as {@code 1.0.0}, so
 *       {@code 1.0.0 == 1.0}. SBOMs and OSV ranges both abbreviate.</li>
 *   <li><b>Extra numeric components.</b> NuGet's fourth field ({@code 1.2.3.4}) is kept and compared,
 *       ranking above {@code 1.2.3}.</li>
 *   <li><b>Dot-separated pre-releases.</b> RubyGems writes {@code 1.0.0.beta1} where SemVer would
 *       write {@code 1.0.0-beta1}. The first dotted component that is not all digits, and everything
 *       after it, becomes the pre-release — which lands {@code 1.0.0.beta1} below {@code 1.0.0},
 *       exactly as RubyGems orders it.</li>
 * </ol>
 *
 * <p>A leading {@code v} is stripped, which is also what makes {@link GoScheme} a thin wrapper.
 */
public class SemVerScheme implements VersionScheme {

    static final SemVerScheme INSTANCE = new SemVerScheme();

    SemVerScheme() {
    }

    @Override
    public String name() {
        return "semver";
    }

    @Override
    public int compare(String a, String b) {
        if (a == null || b == null) {
            return a == null ? (b == null ? 0 : -1) : 1;
        }
        Parsed left = parse(normalize(a));
        Parsed right = parse(normalize(b));

        int c = compareRelease(left.release(), right.release());
        if (c != 0) {
            return c;
        }
        return comparePreRelease(left.preRelease(), right.preRelease());
    }

    /**
     * Hook for {@link GoScheme}: strip whatever decoration the ecosystem puts around an otherwise
     * SemVer string before parsing.
     */
    protected String normalize(String version) {
        return version.trim();
    }

    /* ------------------------------------------------------------------ */
    /* Parsing                                                            */
    /* ------------------------------------------------------------------ */

    private record Parsed(List<BigInteger> release, List<String> preRelease) {
    }

    private static Parsed parse(String raw) {
        String version = raw;
        if (version.length() > 1
                && (version.charAt(0) == 'v' || version.charAt(0) == 'V')
                && Character.isDigit(version.charAt(1))) {
            version = version.substring(1);
        }

        // Build metadata carries no ordering weight.
        int plus = version.indexOf('+');
        if (plus >= 0) {
            version = version.substring(0, plus);
        }

        String core = version;
        String pre = null;
        int dash = version.indexOf('-');
        if (dash >= 0) {
            core = version.substring(0, dash);
            pre = version.substring(dash + 1);
        }

        List<BigInteger> release = new ArrayList<>();
        List<String> preRelease = new ArrayList<>();

        String[] components = core.isEmpty() ? new String[0] : core.split("\\.");
        int i = 0;
        for (; i < components.length; i++) {
            if (!GenericScheme.isNumeric(components[i])) {
                break;
            }
            release.add(new BigInteger(components[i]));
        }
        // Everything from the first non-numeric component onward is a RubyGems-style pre-release.
        for (; i < components.length; i++) {
            if (!components[i].isEmpty()) {
                preRelease.add(components[i]);
            }
        }
        if (pre != null) {
            for (String identifier : pre.split("\\.")) {
                if (!identifier.isEmpty()) {
                    preRelease.add(identifier);
                }
            }
        }

        return new Parsed(release, preRelease);
    }

    /* ------------------------------------------------------------------ */
    /* Ordering                                                           */
    /* ------------------------------------------------------------------ */

    private static int compareRelease(List<BigInteger> left, List<BigInteger> right) {
        int length = Math.max(left.size(), right.size());
        for (int i = 0; i < length; i++) {
            BigInteger l = i < left.size() ? left.get(i) : BigInteger.ZERO;
            BigInteger r = i < right.size() ? right.get(i) : BigInteger.ZERO;
            int c = l.compareTo(r);
            if (c != 0) {
                return c;
            }
        }
        return 0;
    }

    private static int comparePreRelease(List<String> left, List<String> right) {
        if (left.isEmpty() && right.isEmpty()) {
            return 0;
        }
        // "A pre-release version has lower precedence than the associated normal version."
        if (left.isEmpty()) {
            return 1;
        }
        if (right.isEmpty()) {
            return -1;
        }

        int length = Math.min(left.size(), right.size());
        for (int i = 0; i < length; i++) {
            int c = compareIdentifier(left.get(i), right.get(i));
            if (c != 0) {
                return c;
            }
        }
        return Integer.compare(left.size(), right.size());
    }

    private static int compareIdentifier(String left, String right) {
        boolean lNum = GenericScheme.isNumeric(left);
        boolean rNum = GenericScheme.isNumeric(right);
        if (lNum && rNum) {
            return new BigInteger(left).compareTo(new BigInteger(right));
        }
        // "Numeric identifiers always have lower precedence than non-numeric identifiers."
        if (lNum) {
            return -1;
        }
        if (rNum) {
            return 1;
        }
        return left.compareTo(right);
    }

}
