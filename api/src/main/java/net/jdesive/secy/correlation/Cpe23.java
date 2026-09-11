package net.jdesive.secy.correlation;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * A parsed CPE 2.3 formatted-string binding.
 *
 * <p>The format is thirteen colon-separated fields:
 *
 * <pre>
 * cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
 * </pre>
 *
 * <p>Two things make {@code String.split(":")} wrong, and both bit the code this replaces:
 *
 * <ol>
 *   <li><b>Escaping.</b> Any of the eleven attribute values may contain a backslash-escaped colon,
 *       and they do — {@code cpe:2.3:a:vendor:product:1.0\:beta:*:…}. Splitting naively shifts every
 *       field after it by one, so the "version" read out of such a row is somebody else's
 *       {@code update} field.</li>
 *   <li><b>The two special values.</b> {@code *} means ANY and {@code -} means NA (not applicable).
 *       {@code *} in the version field is the common case on modern rows, and reading it as a
 *       version literal is what made every component match every CVE.</li>
 * </ol>
 *
 * <p>Values are returned unescaped and lowercased — CPE names are case-insensitive by
 * specification, and NVD emits them lowercase anyway.
 *
 * @param part      {@code a} (application), {@code o} (OS) or {@code h} (hardware)
 * @param vendor    vendor id
 * @param product   product id
 * @param version   version, or {@code *} / {@code -}
 * @param update    update / patch level
 * @param edition   legacy edition field
 * @param language  language tag
 * @param swEdition software edition
 * @param targetSw  the software environment the product runs in
 * @param targetHw  the hardware environment
 * @param other     free field
 */
public record Cpe23(String part, String vendor, String product, String version, String update,
                    String edition, String language, String swEdition, String targetSw,
                    String targetHw, String other) {

    /** The ANY value. In the version field it means "every version of this product". */
    public static final String ANY = "*";

    /** The NA value. In the version field it means "versionless product". */
    public static final String NA = "-";

    private static final String PREFIX = "cpe:2.3:";

    private static final int ATTRIBUTE_COUNT = 11;

    /**
     * Parse a CPE 2.3 formatted string, or return empty when it is not one.
     *
     * <p>Rows with fewer than the eleven attributes are accepted and the missing tail is filled with
     * {@link #ANY}: NVD is consistent, but a hand-written CPE in a test fixture or a VEX document is
     * not, and refusing them would drop real matches.
     */
    public static Optional<Cpe23> parse(String criteria) {
        if (criteria == null) {
            return Optional.empty();
        }
        String trimmed = criteria.trim();
        if (!trimmed.regionMatches(true, 0, PREFIX, 0, PREFIX.length())) {
            return Optional.empty();
        }

        List<String> fields = splitEscaped(trimmed.substring(PREFIX.length()));
        while (fields.size() < ATTRIBUTE_COUNT) {
            fields.add(ANY);
        }

        return Optional.of(new Cpe23(
                normalize(fields.get(0)), normalize(fields.get(1)), normalize(fields.get(2)),
                normalize(fields.get(3)), normalize(fields.get(4)), normalize(fields.get(5)),
                normalize(fields.get(6)), normalize(fields.get(7)), normalize(fields.get(8)),
                normalize(fields.get(9)), normalize(fields.get(10))));
    }

    /** Split on colons that are not preceded by an odd number of backslashes. */
    private static List<String> splitEscaped(String value) {
        List<String> fields = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean escaped = false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (escaped) {
                current.append(c);
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == ':') {
                fields.add(current.toString());
                current.setLength(0);
            } else {
                current.append(c);
            }
        }
        if (escaped) {
            // A trailing lone backslash. Keep it rather than dropping a character.
            current.append('\\');
        }
        fields.add(current.toString());
        return fields;
    }

    private static String normalize(String value) {
        if (value == null || value.isEmpty()) {
            return ANY;
        }
        return value.toLowerCase(Locale.ROOT);
    }

    /** True when this row names an application rather than an OS or a piece of hardware. */
    public boolean isApplication() {
        return "a".equals(part);
    }

    /** True when the version field is a wildcard, i.e. every version of the product is affected. */
    public boolean isAnyVersion() {
        return ANY.equals(version) || NA.equals(version);
    }

    /** True when the version field names a concrete version that can be compared. */
    public boolean hasConcreteVersion() {
        return !isAnyVersion() && version != null && !version.isBlank();
    }

    /** True when {@code candidate} equals this row's vendor, case-insensitively, or the row says ANY. */
    public boolean vendorMatches(String candidate) {
        return ANY.equals(vendor) || (candidate != null && vendor.equalsIgnoreCase(candidate.trim()));
    }

    /** True when {@code candidate} equals this row's product, case-insensitively, or the row says ANY. */
    public boolean productMatches(String candidate) {
        return ANY.equals(product) || (candidate != null && product.equalsIgnoreCase(candidate.trim()));
    }

}
