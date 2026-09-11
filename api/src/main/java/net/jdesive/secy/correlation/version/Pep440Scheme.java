package net.jdesive.secy.correlation.version;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * PEP 440 ordering — PyPI.
 *
 * <p>A Python version is
 * {@code [N!]N(.N)*[{a|b|rc}N][.postN][.devN][+local]} and the ordering is <em>not</em> SemVer:
 *
 * <ul>
 *   <li>an <b>epoch</b> ({@code 1!1.0}) outranks everything without one, whatever the release
 *       numbers say — it exists precisely to let a project restart its numbering;</li>
 *   <li>a <b>post-release</b> ({@code 1.0.post1}) sorts <b>above</b> {@code 1.0}, unlike anything in
 *       SemVer;</li>
 *   <li>a <b>dev release</b> sorts below the pre-release it belongs to
 *       ({@code 1.0.dev1 < 1.0a1 < 1.0 < 1.0.post1});</li>
 *   <li>trailing zeros are insignificant: {@code 1.0 == 1.0.0}.</li>
 * </ul>
 *
 * <p>Normalization follows the spec's alias table before parsing: case is folded, {@code -} and
 * {@code _} become {@code .}, {@code alpha}/{@code beta}/{@code c}/{@code pre}/{@code preview}
 * collapse onto {@code a}/{@code b}/{@code rc}, and {@code rev}/{@code r} onto {@code post}, so
 * {@code 1.0-alpha.1}, {@code 1.0.a1} and {@code 1.0a1} are one version.
 *
 * <p>The sort key mirrors the reference implementation in {@code packaging}: absent segments become
 * infinities rather than zeros, which is what makes "no pre-release" rank above every pre-release
 * while "no post-release" ranks below every post-release. A local version ({@code +ubuntu1}) ranks
 * above the same version without one; its segments are otherwise compared the same way.
 *
 * <p>Anything that does not parse as PEP 440 at all falls through to {@link GenericScheme} rather
 * than throwing.
 */
public final class Pep440Scheme implements VersionScheme {

    static final Pep440Scheme INSTANCE = new Pep440Scheme();

    private static final Pattern PATTERN = Pattern.compile(
            "^(?:(?<epoch>\\d+)!)?"
                    + "(?<release>\\d+(?:\\.\\d+)*)"
                    + "(?:\\.?(?<preLabel>a|b|rc)\\.?(?<preNum>\\d+)?)?"
                    + "(?:\\.?(?<postLabel>post)\\.?(?<postNum>\\d+)?)?"
                    + "(?:\\.?(?<devLabel>dev)\\.?(?<devNum>\\d+)?)?"
                    + "(?:\\+(?<local>[a-z0-9.]+))?$");

    /** Sorts below every real segment number. */
    private static final BigInteger NEGATIVE_INFINITY = BigInteger.valueOf(Long.MIN_VALUE);

    /** Sorts above every real segment number. */
    private static final BigInteger POSITIVE_INFINITY = BigInteger.valueOf(Long.MAX_VALUE);

    Pep440Scheme() {
    }

    @Override
    public String name() {
        return "pep440";
    }

    @Override
    public int compare(String a, String b) {
        if (a == null || b == null) {
            return a == null ? (b == null ? 0 : -1) : 1;
        }
        Key left = key(a);
        Key right = key(b);
        if (left == null || right == null) {
            // At least one side is not a Python version at all — order both tolerantly instead.
            return GenericScheme.INSTANCE.compare(a, b);
        }
        return left.compareTo(right);
    }

    /* ------------------------------------------------------------------ */
    /* Parsing                                                            */
    /* ------------------------------------------------------------------ */

    static String normalize(String version) {
        String normalized = version.trim().toLowerCase(Locale.ROOT);
        if (normalized.startsWith("v")) {
            normalized = normalized.substring(1);
        }
        normalized = normalized.replace('-', '.').replace('_', '.');
        // Spec aliases. Longest first so "preview" is not eaten by "pre".
        normalized = normalized.replace("preview", "rc").replace("alpha", "a").replace("beta", "b");
        normalized = normalized.replaceAll("(?<=\\d)\\.?pre\\.?(?=\\d|$)", "rc");
        normalized = normalized.replaceAll("(?<=\\d)\\.?c\\.?(?=\\d|$)", "rc");
        normalized = normalized.replaceAll("(?<=\\d)\\.?rev\\.?(?=\\d|$)", ".post");
        normalized = normalized.replaceAll("(?<=\\d)\\.?r\\.?(?=\\d)", ".post");
        // "1.0-1" is a shorthand for "1.0.post1"; we do not attempt it — the ".post" spelling is
        // what OSV and PyPI metadata actually carry.
        return normalized;
    }

    private static Key key(String raw) {
        Matcher matcher = PATTERN.matcher(normalize(raw));
        if (!matcher.matches()) {
            return null;
        }

        BigInteger epoch = matcher.group("epoch") == null
                ? BigInteger.ZERO
                : new BigInteger(matcher.group("epoch"));

        List<BigInteger> release = new ArrayList<>();
        for (String component : matcher.group("release").split("\\.")) {
            release.add(new BigInteger(component));
        }
        // Trailing zeros carry no meaning: 1.0 == 1.0.0.
        while (release.size() > 1 && release.get(release.size() - 1).signum() == 0) {
            release.remove(release.size() - 1);
        }

        String preLabel = matcher.group("preLabel");
        BigInteger preNum = number(matcher.group("preNum"));
        BigInteger postNum = matcher.group("postLabel") == null ? null : number(matcher.group("postNum"));
        BigInteger devNum = matcher.group("devLabel") == null ? null : number(matcher.group("devNum"));
        String local = matcher.group("local");

        // packaging's rule, verbatim: a bare dev release ranks below every pre-release of the same
        // release, an absent pre-release ranks above them all, an absent post-release below them
        // all, and an absent dev release above them all.
        int preRank;
        String preLetter;
        if (preLabel == null && postNum == null && devNum != null) {
            preRank = -1;
            preLetter = "";
        } else if (preLabel == null) {
            preRank = 1;
            preLetter = "";
        } else {
            preRank = 0;
            preLetter = preLabel;
        }

        return new Key(epoch, release, preRank, preLetter, preNum == null ? BigInteger.ZERO : preNum,
                postNum == null ? NEGATIVE_INFINITY : postNum,
                devNum == null ? POSITIVE_INFINITY : devNum,
                local);
    }

    private static BigInteger number(String group) {
        return group == null ? BigInteger.ZERO : new BigInteger(group);
    }

    /* ------------------------------------------------------------------ */
    /* The sort key                                                       */
    /* ------------------------------------------------------------------ */

    private record Key(BigInteger epoch, List<BigInteger> release, int preRank, String preLetter,
                       BigInteger preNum, BigInteger post, BigInteger dev, String local)
            implements Comparable<Key> {

        @Override
        public int compareTo(Key other) {
            int c = epoch.compareTo(other.epoch);
            if (c != 0) {
                return c;
            }
            c = compareRelease(release, other.release);
            if (c != 0) {
                return c;
            }
            c = Integer.compare(preRank, other.preRank);
            if (c != 0) {
                return c;
            }
            c = preLetter.compareTo(other.preLetter);
            if (c != 0) {
                return c;
            }
            c = preNum.compareTo(other.preNum);
            if (c != 0) {
                return c;
            }
            c = post.compareTo(other.post);
            if (c != 0) {
                return c;
            }
            c = dev.compareTo(other.dev);
            if (c != 0) {
                return c;
            }
            if (local == null && other.local == null) {
                return 0;
            }
            if (local == null) {
                return -1;
            }
            if (other.local == null) {
                return 1;
            }
            return local.compareTo(other.local);
        }

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
    }

}
