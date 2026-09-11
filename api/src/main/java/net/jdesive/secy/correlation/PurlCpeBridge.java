package net.jdesive.secy.correlation;

import net.jdesive.secy.persistence.entity.MatchConfidence;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Guesses the CPE vendor and product for a package coordinate.
 *
 * <p>PURL and CPE do not share an identifier space and never will. PURL says
 * {@code pkg:maven/org.apache.logging.log4j/log4j-core}; NVD says
 * {@code cpe:2.3:a:apache:log4j:…}. Nobody maintains a complete mapping between them — that is the
 * whole reason OSV exists and the whole reason this class is the <b>fallback</b>, reached only for
 * packages OSV has never heard of and (from Phase 4) for OS and firmware assets that were never in
 * a package ecosystem to begin with.
 *
 * <h2>The rules</h2>
 *
 * <p>Each candidate carries a <b>confidence ceiling</b>: the best a match found through it can ever
 * be. A candidate that names both a vendor and a product is a real identity claim and can reach
 * {@link MatchConfidence#RANGE}; a product-only candidate is a name collision waiting to happen —
 * "core", "common", "server" are products of a hundred vendors — and is capped at
 * {@link MatchConfidence#HEURISTIC} however well its version range fits.
 *
 * <table border="1">
 *   <caption>PURL type to CPE candidates</caption>
 *   <tr><th>type</th><th>vendor guess</th><th>product guess</th></tr>
 *   <tr><td>{@code maven}</td><td>last segment of the groupId ({@code org.apache.commons} → {@code apache})</td><td>artifactId</td></tr>
 *   <tr><td>{@code golang}</td><td>the org in the module path ({@code github.com/gorilla/mux} → {@code gorilla})</td><td>last path segment</td></tr>
 *   <tr><td>{@code npm}, {@code composer}</td><td>the scope / vendor, when there is one</td><td>package name</td></tr>
 *   <tr><td>{@code pypi}, {@code gem}, {@code nuget}, {@code cargo}</td><td>the package name itself — single-project vendors are the norm</td><td>package name</td></tr>
 *   <tr><td>anything else, or no PURL</td><td>—</td><td>the component name</td></tr>
 * </table>
 *
 * <p>Every type also emits the product-only candidate as a backstop, so a wrong vendor guess costs
 * confidence rather than the match.
 */
public final class PurlCpeBridge {

    /**
     * One CPE identity to look for.
     *
     * @param vendor   CPE vendor to require, or null to accept any vendor
     * @param product  CPE product to require; never null
     * @param ceiling  the strongest confidence a match through this candidate may claim
     */
    public record CpeCandidate(String vendor, String product, MatchConfidence ceiling) {

        /**
         * The {@code LIKE} pattern that selects the {@code cpe_match} rows worth parsing.
         *
         * <p>{@code LIKE} metacharacters in the name are deliberately <b>not</b> escaped. An
         * underscore is common in CPE product ids and leaving it as a single-character wildcard only
         * widens the candidate set; {@link Cpe23#productMatches} then compares the parsed product
         * for equality, so a widened query costs a few extra rows to parse and can never produce a
         * match the strict comparison would have rejected. Escaping would need a dialect-specific
         * {@code ESCAPE} clause for no correctness gain.
         */
        public String criteriaPattern() {
            String vendorPart = vendor == null ? "%" : vendor.toLowerCase(Locale.ROOT);
            return "cpe:2.3:%:" + vendorPart + ":" + product.toLowerCase(Locale.ROOT) + ":%";
        }
    }

    private PurlCpeBridge() {
    }

    /**
     * The CPE identities worth looking for, strongest first.
     *
     * <p>Empty when the coordinate carries no usable name at all.
     */
    public static List<CpeCandidate> candidatesFor(ComponentCoordinate coordinate) {
        if (coordinate == null) {
            return List.of();
        }
        String product = coordinate.simpleName();
        if (product == null || product.isBlank()) {
            return List.of();
        }

        Set<String> vendors = new LinkedHashSet<>();
        String type = coordinate.purlType();
        String namespace = coordinate.namespace();

        if (type != null) {
            switch (type) {
                case "maven" -> {
                    // groupId's last meaningful segment is the vendor NVD usually names:
                    // org.apache.logging.log4j -> log4j, but apache is the actual CPE vendor, so
                    // offer both the tail and the segment after the TLD-ish prefix.
                    if (namespace != null) {
                        String[] segments = namespace.split("\\.");
                        if (segments.length > 0) {
                            vendors.add(segments[segments.length - 1]);
                        }
                        if (segments.length > 1) {
                            vendors.add(segments[1]);
                        }
                    }
                }
                case "golang" -> {
                    // github.com/gorilla/mux -> gorilla
                    if (namespace != null) {
                        String[] segments = namespace.split("/");
                        if (segments.length > 1) {
                            vendors.add(segments[segments.length - 1]);
                        }
                    }
                }
                case "npm", "composer", "conan", "swift" -> {
                    if (namespace != null && !namespace.isBlank()) {
                        vendors.add(namespace.startsWith("@") ? namespace.substring(1) : namespace);
                    }
                    vendors.add(product);
                }
                case "pypi", "gem", "nuget", "cargo", "hex", "pub", "cran" ->
                    // These ecosystems are overwhelmingly single-project: NVD names the project as
                    // both vendor and product ("requests"/"requests", "nokogiri"/"nokogiri").
                        vendors.add(product);
                default -> {
                    // Unknown PURL type: no convention to lean on. Fall through to product-only.
                }
            }
        }

        List<CpeCandidate> candidates = new ArrayList<>();
        for (String vendor : vendors) {
            if (vendor != null && !vendor.isBlank()) {
                candidates.add(new CpeCandidate(vendor.toLowerCase(Locale.ROOT),
                        product.toLowerCase(Locale.ROOT), MatchConfidence.RANGE));
            }
        }
        // Always keep the broad backstop: a wrong vendor guess should cost confidence, not the match.
        candidates.add(new CpeCandidate(null, product.toLowerCase(Locale.ROOT), MatchConfidence.HEURISTIC));
        return candidates;
    }

}
