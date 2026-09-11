package net.jdesive.secy.correlation;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import net.jdesive.secy.persistence.entity.SBOMComponent;

import java.util.Locale;
import java.util.Map;

/**
 * "One thing you ship, identified well enough to look up."
 *
 * <p>This is the seam between the storage model and the correlation engine. Everything downstream —
 * the OSV matcher, the CPE bridge, the version schemes — takes a {@code ComponentCoordinate} and
 * never sees a {@link SBOMComponent}. When Phase 3 replaces {@code SBOMComponent} with
 * {@code NormalizedComponent}, {@link #of(SBOMComponent)} gains a sibling and nothing else in this
 * package changes.
 *
 * <h2>Naming</h2>
 *
 * <p>{@link #name} is spelled the way the <em>ecosystem</em> spells it, because that is how OSV
 * indexes packages and a lookup that spells it differently finds nothing:
 *
 * <table border="1">
 *   <caption>PURL to OSV package name</caption>
 *   <tr><th>PURL</th><th>ecosystem</th><th>name</th></tr>
 *   <tr><td>{@code pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1}</td><td>Maven</td><td>{@code org.apache.logging.log4j:log4j-core}</td></tr>
 *   <tr><td>{@code pkg:npm/%40angular/core@12.0.0}</td><td>npm</td><td>{@code @angular/core}</td></tr>
 *   <tr><td>{@code pkg:golang/github.com/gorilla/mux@v1.7.3}</td><td>Go</td><td>{@code github.com/gorilla/mux}</td></tr>
 *   <tr><td>{@code pkg:pypi/django@3.2}</td><td>PyPI</td><td>{@code django}</td></tr>
 * </table>
 *
 * @param purl      the raw PURL as the SBOM declared it, or null when it declared none
 * @param purlType  the PURL type ({@code maven}, {@code npm}, …), or null
 * @param ecosystem the OSV ecosystem name, or null when the PURL type has no OSV counterpart
 * @param namespace the PURL namespace — groupId, npm scope, Go module prefix — or null
 * @param name      the ecosystem-native package name; falls back to the component name with no PURL
 * @param version   the version the SBOM declared, or null
 */
public record ComponentCoordinate(String purl, String purlType, String ecosystem,
                                  String namespace, String name, String version) {

    /**
     * PURL type to OSV ecosystem. Only types OSV actually indexes appear here; a type that is
     * absent leaves {@link #ecosystem} null, which sends the component straight to the CPE fallback.
     */
    private static final Map<String, String> ECOSYSTEMS = Map.ofEntries(
            Map.entry("npm", "npm"),
            Map.entry("maven", "Maven"),
            Map.entry("pypi", "PyPI"),
            Map.entry("golang", "Go"),
            Map.entry("nuget", "NuGet"),
            Map.entry("gem", "RubyGems"),
            Map.entry("cargo", "crates.io"),
            Map.entry("composer", "Packagist"),
            Map.entry("hex", "Hex"),
            Map.entry("pub", "Pub"),
            Map.entry("hackage", "Hackage"),
            Map.entry("cran", "CRAN"),
            Map.entry("conan", "ConanCenter"),
            Map.entry("swift", "SwiftURL"));

    /**
     * Read a coordinate off an SBOM component.
     *
     * <p>Never throws and never returns null: a malformed or absent PURL degrades to a coordinate
     * with the component's own name and version and no ecosystem, which still correlates through the
     * CPE fallback. Losing a component to a parse error would be a silent false negative, which is
     * the failure mode this whole phase exists to remove.
     */
    public static ComponentCoordinate of(SBOMComponent component) {
        if (component == null) {
            return new ComponentCoordinate(null, null, null, null, null, null);
        }
        return of(component.getPurl(), component.getName(), component.getVersion());
    }

    /** @see #of(SBOMComponent) */
    public static ComponentCoordinate of(String purl, String fallbackName, String fallbackVersion) {
        if (purl == null || purl.isBlank()) {
            return new ComponentCoordinate(null, null, null, null, trimToNull(fallbackName), trimToNull(fallbackVersion));
        }

        PackageURL parsed;
        try {
            parsed = new PackageURL(purl.trim());
        } catch (MalformedPackageURLException e) {
            return new ComponentCoordinate(purl.trim(), null, null, null,
                    trimToNull(fallbackName), trimToNull(fallbackVersion));
        }

        String type = parsed.getType() == null ? null : parsed.getType().toLowerCase(Locale.ROOT);
        String namespace = trimToNull(parsed.getNamespace());
        String bare = trimToNull(parsed.getName());
        String version = trimToNull(parsed.getVersion());
        if (version == null) {
            version = trimToNull(fallbackVersion);
        }

        return new ComponentCoordinate(purl.trim(), type, ECOSYSTEMS.get(type), namespace,
                ecosystemName(type, namespace, bare == null ? trimToNull(fallbackName) : bare),
                version);
    }

    /** Join namespace and name the way the ecosystem's own index spells the package. */
    private static String ecosystemName(String type, String namespace, String name) {
        if (name == null) {
            return null;
        }
        if (namespace == null || namespace.isBlank()) {
            return name;
        }
        if ("maven".equals(type)) {
            return namespace + ":" + name;
        }
        // npm scopes, Go module paths, Composer vendors, Conan users, Swift URLs: all slash-joined.
        return namespace + "/" + name;
    }

    /** True when OSV could plausibly know this package — the precondition for the primary path. */
    public boolean hasEcosystem() {
        return ecosystem != null && name != null && !name.isBlank();
    }

    /** True when there is a version to test a range against. */
    public boolean isVersioned() {
        return version != null && !version.isBlank();
    }

    /**
     * The last path segment of {@link #name} — {@code mux} for {@code github.com/gorilla/mux},
     * {@code core} for {@code @angular/core}, {@code log4j-core} for the Maven coordinate.
     *
     * <p>This is the string a CPE {@code product} field is most likely to hold, since CPE has no
     * concept of a namespace.
     */
    public String simpleName() {
        if (name == null) {
            return null;
        }
        int slash = name.lastIndexOf('/');
        int colon = name.lastIndexOf(':');
        int cut = Math.max(slash, colon);
        return cut >= 0 && cut + 1 < name.length() ? name.substring(cut + 1) : name;
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

}
