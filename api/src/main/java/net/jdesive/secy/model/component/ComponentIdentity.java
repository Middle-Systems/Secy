package net.jdesive.secy.model.component;

import net.jdesive.secy.correlation.ComponentCoordinate;

import java.util.Locale;

/**
 * The stable identity of a component <em>within a product</em>, across SBOM versions.
 *
 * <h2>Why this exists</h2>
 *
 * <p>Phase 2 built the alert lifecycle ({@code ACTIVE} ↔ {@code AUTO_RESOLVED}, "upsert, never
 * duplicate") on the key {@code (component_id, cveId)}. That key only held <em>within one SBOM's own
 * re-correlation</em>: every upload created brand-new {@code sbom_component} rows, so a second SBOM
 * for the same product produced all-new component ids, every alert looked new again, and nothing was
 * ever auto-resolved by a subsequent upload. This class supplies the missing half — an identity that
 * survives the upload — and correlation keys on {@code (identity, cveId)} instead.
 *
 * <h2>The key deliberately excludes the version</h2>
 *
 * <p>A PURL encodes the version, so {@code pkg:npm/lodash@4.17.20} and {@code pkg:npm/lodash@4.17.21}
 * are different strings for what an operator calls <em>the same dependency, upgraded</em>. Keying on
 * the raw PURL would make every version bump look like a component removal plus a component
 * addition, which is exactly the bug this phase fixes. The key is therefore the
 * <b>version-less PURL</b> — type plus ecosystem-native name — with {@code version} left as a mutable
 * field on the row. That is what makes the headline case work: <em>lodash 4.17.20 is vulnerable →
 * alert ACTIVE; next upload ships 4.17.21 → the same alert auto-resolves</em>.
 *
 * <h2>Spelling</h2>
 *
 * <p>The name half is derived by {@link ComponentCoordinate}, not re-derived here, so a component's
 * identity is spelled exactly the way its OSV lookup is spelled and the two can never drift:
 *
 * <table border="1">
 *   <caption>PURL to identity key</caption>
 *   <tr><th>PURL</th><th>identity key</th></tr>
 *   <tr><td>{@code pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1}</td><td>{@code maven/org.apache.logging.log4j:log4j-core}</td></tr>
 *   <tr><td>{@code pkg:npm/%40angular/core@12.0.0}</td><td>{@code npm/@angular/core}</td></tr>
 *   <tr><td>{@code pkg:golang/github.com/gorilla/mux@v1.7.3}</td><td>{@code golang/github.com/gorilla/mux}</td></tr>
 *   <tr><td>(none), component named {@code OpenSSL}</td><td>{@code name/openssl}</td></tr>
 * </table>
 *
 * <p>The {@code name/} prefix keeps the no-PURL namespace disjoint from the PURL one, so a component
 * literally named {@code npm/lodash} can never collide with {@code pkg:npm/lodash}.
 *
 * <h2>Known collapse</h2>
 *
 * <p>One SBOM that ships two versions of the same package (a bundler shading both {@code lodash
 * 4.17.20} and {@code 4.17.21}) yields two rows with one identity. Correlation merges their matches
 * with {@code CorrelationMatch::best}, so the surviving alert describes the worse of the two — "this
 * product ships a vulnerable lodash", which is the true statement. Accepted, not overlooked.
 */
public final class ComponentIdentity {

    /** Matches {@code sbom_component.identity_key}. Go module paths are the long tail here. */
    public static final int MAX_LENGTH = 512;

    private ComponentIdentity() {
    }

    /**
     * The identity key for a component, or {@code null} when it has neither a usable PURL nor a name
     * and therefore cannot be carried forward at all.
     *
     * <p>Never throws: a malformed PURL degrades to the name-based key rather than losing the
     * component, for the same reason {@link ComponentCoordinate#of} never throws.
     */
    public static String keyOf(String purl, String name) {
        ComponentCoordinate coordinate = ComponentCoordinate.of(purl, name, null);

        if (coordinate.purlType() != null && coordinate.name() != null && !coordinate.name().isBlank()) {
            return truncate((coordinate.purlType() + "/" + coordinate.name()).toLowerCase(Locale.ROOT));
        }

        String bare = name == null ? null : name.trim();
        if (bare == null || bare.isEmpty()) {
            return null;
        }
        return truncate("name/" + bare.toLowerCase(Locale.ROOT));
    }

    private static String truncate(String key) {
        return key.length() <= MAX_LENGTH ? key : key.substring(0, MAX_LENGTH);
    }

}
