package net.jdesive.secy.correlation.version;

import java.util.Locale;
import java.util.Map;

/**
 * The one place that decides which ordering an ecosystem gets.
 *
 * <p>Keys are OSV ecosystem names (the {@code affected[].package.ecosystem} field, and the directory
 * name in OSV's per-ecosystem exports) and, as aliases, the PURL types that map onto them. Lookup is
 * case- and suffix-insensitive: OSV appends a release qualifier to some ecosystems
 * ({@code "Alpine:v3.16"}, {@code "Debian:11"}), and only the part before the colon selects an
 * ordering.
 *
 * <p>An unknown ecosystem gets {@link GenericScheme} — tolerant, never wrong enough to crash, and
 * the honest answer when we do not know how a corpus orders itself. That is also what the NVD CPE
 * fallback path always uses, since a CPE row carries no ecosystem at all.
 */
public final class VersionSchemes {

    private static final Map<String, VersionScheme> BY_ECOSYSTEM = Map.ofEntries(
            // SemVer, or close enough that the tolerant parser lands on the same order.
            Map.entry("npm", SemVerScheme.INSTANCE),
            Map.entry("crates.io", SemVerScheme.INSTANCE),
            Map.entry("cargo", SemVerScheme.INSTANCE),
            Map.entry("nuget", SemVerScheme.INSTANCE),
            Map.entry("rubygems", SemVerScheme.INSTANCE),
            Map.entry("gem", SemVerScheme.INSTANCE),
            Map.entry("hex", SemVerScheme.INSTANCE),
            Map.entry("packagist", SemVerScheme.INSTANCE),
            Map.entry("composer", SemVerScheme.INSTANCE),
            Map.entry("pub", SemVerScheme.INSTANCE),
            Map.entry("hackage", SemVerScheme.INSTANCE),
            Map.entry("swifturl", SemVerScheme.INSTANCE),
            Map.entry("swift", SemVerScheme.INSTANCE),
            Map.entry("bitnami", SemVerScheme.INSTANCE),

            // Go's v-prefix and +incompatible suffix on top of SemVer.
            Map.entry("go", GoScheme.INSTANCE),
            Map.entry("golang", GoScheme.INSTANCE),

            // PEP 440 — epochs, post-releases and dev-releases order nothing like SemVer.
            Map.entry("pypi", Pep440Scheme.INSTANCE),

            // Maven's own ComparableVersion.
            Map.entry("maven", MavenScheme.INSTANCE));

    private VersionSchemes() {
    }

    /**
     * The ordering for an OSV ecosystem name or a PURL type.
     *
     * @param ecosystem e.g. {@code "npm"}, {@code "PyPI"}, {@code "Maven"}, {@code "Alpine:v3.16"};
     *                  {@code null} or unknown yields {@link #generic()}
     */
    public static VersionScheme forEcosystem(String ecosystem) {
        if (ecosystem == null || ecosystem.isBlank()) {
            return GenericScheme.INSTANCE;
        }
        String key = ecosystem.trim().toLowerCase(Locale.ROOT);
        int colon = key.indexOf(':');
        if (colon > 0) {
            key = key.substring(0, colon);
        }
        return BY_ECOSYSTEM.getOrDefault(key, GenericScheme.INSTANCE);
    }

    /**
     * The tolerant fallback ordering. Used verbatim by the NVD CPE path, where version strings come
     * from a corpus with no ecosystem and no convention.
     */
    public static VersionScheme generic() {
        return GenericScheme.INSTANCE;
    }

    /** True when {@link #forEcosystem} has a real ordering for this name rather than the fallback. */
    public static boolean isKnown(String ecosystem) {
        return forEcosystem(ecosystem) != GenericScheme.INSTANCE;
    }

}
