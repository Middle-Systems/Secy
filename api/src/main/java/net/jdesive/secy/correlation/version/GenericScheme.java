package net.jdesive.secy.correlation.version;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * The tolerant fallback ordering, and the one the NVD CPE path always uses.
 *
 * <p>This is the direct descendant of the old {@code net.jdesive.secy.util.Version}: dotted numeric
 * versions compare component-by-component with missing components treated as zero, so
 * {@code 1.0 == 1.0.0} and {@code 1.9 < 1.10}. Everything the old class threw
 * {@code IllegalArgumentException} for, this one handles instead, because CPE version fields are
 * not clean dotted integers — they are things like {@code 1.1.1g}, {@code 8.0.0-beta}, {@code 4u261}
 * and {@code 2.4.49}.
 *
 * <p><b>Deliberate divergence from SemVer:</b> a trailing alphabetic run sorts <em>above</em> the
 * bare number, so {@code 1.1.1g > 1.1.1}. That is wrong for SemVer (where {@code -rc1} is a
 * pre-release and sorts below) and right for the CPE corpus, where letters are OpenSSL-style patch
 * levels. Package ecosystems never reach this class — they get {@link SemVerScheme},
 * {@link Pep440Scheme}, {@link MavenScheme} or {@link GoScheme} — so the two conventions do not
 * collide.
 */
public final class GenericScheme implements VersionScheme {

    static final GenericScheme INSTANCE = new GenericScheme();

    /** Separators that delimit version components across every corpus we see. */
    private static final String SEPARATORS = "[.\\-_+~:]";

    GenericScheme() {
    }

    @Override
    public String name() {
        return "generic";
    }

    @Override
    public int compare(String a, String b) {
        if (a == null || b == null) {
            return a == null ? (b == null ? 0 : -1) : 1;
        }

        List<String> left = split(a);
        List<String> right = split(b);
        int length = Math.max(left.size(), right.size());

        for (int i = 0; i < length; i++) {
            String l = i < left.size() ? left.get(i) : null;
            String r = i < right.size() ? right.get(i) : null;
            int c = compareComponent(l, r);
            if (c != 0) {
                return c;
            }
        }
        return 0;
    }

    /** Strip a leading {@code v}/{@code V} and cut the string into separator-delimited components. */
    private static List<String> split(String version) {
        String normalized = version.trim();
        if (normalized.length() > 1
                && (normalized.charAt(0) == 'v' || normalized.charAt(0) == 'V')
                && Character.isDigit(normalized.charAt(1))) {
            normalized = normalized.substring(1);
        }
        List<String> parts = new ArrayList<>();
        for (String part : normalized.split(SEPARATORS)) {
            if (!part.isEmpty()) {
                parts.add(part);
            }
        }
        return parts;
    }

    /**
     * Compare one component. A missing component counts as {@code 0} against a numeric one — that is
     * what makes {@code 1.0 == 1.0.0} — but as "absent, therefore lower" against anything else.
     */
    private static int compareComponent(String left, String right) {
        if (left == null && right == null) {
            return 0;
        }
        if (left == null) {
            return isZero(right) ? 0 : -1;
        }
        if (right == null) {
            return isZero(left) ? 0 : 1;
        }
        return compareMixed(left, right);
    }

    private static boolean isZero(String component) {
        if (!isNumeric(component)) {
            return false;
        }
        return new BigInteger(component).signum() == 0;
    }

    static boolean isNumeric(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            if (!Character.isDigit(value.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    /**
     * Compare two components that may mix digits and letters ({@code 1g} vs {@code 1}, {@code 4u261}
     * vs {@code 4u251}).
     *
     * <p>Each side is cut into alternating digit and letter runs. Digit runs compare numerically —
     * so {@code 4u9 < 4u10}. Letter runs compare case-insensitively. A run present on one side and
     * absent on the other makes the present side greater, which is the OpenSSL patch-letter rule.
     * Across types a letter run outranks a digit run, so {@code 1.0-beta > 1.0.0}; that only bites
     * on data no package ecosystem sends here.
     */
    private static int compareMixed(String left, String right) {
        if (isNumeric(left) && isNumeric(right)) {
            return new BigInteger(left).compareTo(new BigInteger(right));
        }

        List<String> l = tokenize(left);
        List<String> r = tokenize(right);
        int length = Math.max(l.size(), r.size());
        for (int i = 0; i < length; i++) {
            if (i >= l.size()) {
                return -1;
            }
            if (i >= r.size()) {
                return 1;
            }
            String lt = l.get(i);
            String rt = r.get(i);
            boolean lNum = isNumeric(lt);
            boolean rNum = isNumeric(rt);
            int c;
            if (lNum && rNum) {
                c = new BigInteger(lt).compareTo(new BigInteger(rt));
            } else if (lNum) {
                c = -1;
            } else if (rNum) {
                c = 1;
            } else {
                c = lt.compareToIgnoreCase(rt);
            }
            if (c != 0) {
                return c;
            }
        }
        return 0;
    }

    /** Split a component into maximal runs of digits and runs of non-digits. */
    private static List<String> tokenize(String component) {
        List<String> tokens = new ArrayList<>();
        int start = 0;
        boolean digit = Character.isDigit(component.charAt(0));
        for (int i = 1; i <= component.length(); i++) {
            boolean end = i == component.length();
            if (end || Character.isDigit(component.charAt(i)) != digit) {
                tokens.add(component.substring(start, i));
                if (!end) {
                    start = i;
                    digit = !digit;
                }
            }
        }
        return tokens;
    }

}
