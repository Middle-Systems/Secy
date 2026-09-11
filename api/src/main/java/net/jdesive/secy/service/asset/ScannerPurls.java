package net.jdesive.secy.service.asset;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import lombok.extern.slf4j.Slf4j;

import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Turns a scanner's own ecosystem label into a PURL, so a scanned package lands in exactly the same
 * coordinate space an SBOM component does.
 *
 * <h2>Why synthesize at all</h2>
 *
 * <p>Grype emits a PURL for nearly everything, and Trivy 0.50+ emits one in {@code PkgIdentifier}.
 * Older Trivy does not — it gives a {@code PkgName}, an {@code InstalledVersion} and the target's
 * {@code Type}, which is exactly enough to build the PURL it would have emitted. Without one, a
 * {@code lodash 4.17.20} found in an image would fall to the CPE fallback while the identical
 * component in the product's SBOM went through OSV, and the two would disagree. Synthesizing keeps
 * the OSV-primary path available to scanner output.
 *
 * <h2>OS packages deliberately get no PURL</h2>
 *
 * <p>An {@code apk}/{@code deb}/{@code rpm} PURL buys nothing here: none of those types is an OSV
 * ecosystem, and {@code PurlCpeBridge} ignores the type for them anyway, so the package takes the CPE
 * fallback either way. What a PURL <em>would</em> cost is identity stability — its namespace is the
 * distro ({@code pkg:apk/alpine/openssl}), which different scanners and different scanner versions
 * spell differently, so the same package would change identity key when the scanner was upgraded and
 * its alerts would auto-resolve and re-raise for no reason. OS packages therefore keep the
 * name-only identity ({@code name/openssl}), which every scanner agrees on.
 */
@Slf4j
public final class ScannerPurls {

    /**
     * Trivy {@code Results[].Type} for a {@code lang-pkgs} target, mapped to a PURL type.
     *
     * <p>Only types with a PURL counterpart appear; anything absent is left PURL-less rather than
     * guessed, which routes it to the CPE fallback — the honest outcome for something Secy cannot
     * place in an ecosystem.
     */
    private static final Map<String, String> TRIVY_LANG_TYPES = Map.ofEntries(
            Map.entry("npm", "npm"),
            Map.entry("yarn", "npm"),
            Map.entry("pnpm", "npm"),
            Map.entry("node-pkg", "npm"),
            Map.entry("pip", "pypi"),
            Map.entry("poetry", "pypi"),
            Map.entry("pipenv", "pypi"),
            Map.entry("python-pkg", "pypi"),
            Map.entry("gomod", "golang"),
            Map.entry("gobinary", "golang"),
            Map.entry("jar", "maven"),
            Map.entry("pom", "maven"),
            Map.entry("gradle", "maven"),
            Map.entry("sbt", "maven"),
            Map.entry("bundler", "gem"),
            Map.entry("gemspec", "gem"),
            Map.entry("nuget", "nuget"),
            Map.entry("dotnet-core", "nuget"),
            Map.entry("cargo", "cargo"),
            Map.entry("rust-binary", "cargo"),
            Map.entry("composer", "composer"),
            Map.entry("conan", "conan"),
            Map.entry("pub", "pub"),
            Map.entry("hex", "hex"),
            Map.entry("mix", "hex"),
            Map.entry("cocoapods", "cocoapods"),
            Map.entry("swift", "swift"));

    /** Syft/Grype {@code artifact.type} mapped to a PURL type, for the rare artifact with no PURL. */
    private static final Map<String, String> GRYPE_TYPES = Map.ofEntries(
            Map.entry("npm", "npm"),
            Map.entry("python", "pypi"),
            Map.entry("go-module", "golang"),
            Map.entry("java-archive", "maven"),
            Map.entry("jenkins-plugin", "maven"),
            Map.entry("gem", "gem"),
            Map.entry("dotnet", "nuget"),
            Map.entry("nuget", "nuget"),
            Map.entry("rust-crate", "cargo"),
            Map.entry("php-composer", "composer"),
            Map.entry("dart-pub", "pub"),
            Map.entry("hackage", "hackage"),
            Map.entry("conan", "conan"),
            Map.entry("swift", "swift"),
            Map.entry("cocoapods", "cocoapods"));

    /** Scanner type labels that mean "OS package" — no PURL, by the class note. */
    private static final Set<String> OS_TYPES = Set.of(
            "apk", "alpine", "deb", "debian", "ubuntu", "rpm", "redhat", "centos", "rocky",
            "alma", "almalinux", "amazon", "oracle", "suse", "sles", "opensuse",
            "opensuse-leap", "opensuse-tumbleweed", "photon", "wolfi", "chainguard",
            "cbl-mariner", "azurelinux", "bottlerocket", "openeuler", "minimos");

    private ScannerPurls() {
    }

    /** True when a scanner's type label names an operating-system package manager. */
    public static boolean isOsPackageType(String scannerType) {
        return scannerType != null && OS_TYPES.contains(scannerType.trim().toLowerCase(Locale.ROOT));
    }

    /**
     * Build the PURL for a Trivy {@code lang-pkgs} package, or null when its type has no counterpart.
     *
     * @param trivyType Trivy's {@code Results[].Type}
     * @param pkgName   Trivy's {@code PkgName} — for Maven this is {@code groupId:artifactId}
     * @param version   the installed version
     */
    public static String forTrivy(String trivyType, String pkgName, String version) {
        return build(lookUp(TRIVY_LANG_TYPES, trivyType), pkgName, version);
    }

    /** Build the PURL for a Grype artifact whose own {@code purl} was absent. */
    public static String forGrype(String grypeType, String name, String version) {
        return build(lookUp(GRYPE_TYPES, grypeType), name, version);
    }

    /** {@code Map.ofEntries} rejects a null key outright, and a scanner may well omit the type. */
    private static String lookUp(Map<String, String> types, String scannerType) {
        String normalized = normalize(scannerType);
        return normalized == null ? null : types.get(normalized);
    }

    /**
     * Assemble a PURL through {@link PackageURL} rather than string concatenation, so scoped npm
     * names ({@code @angular/core} → {@code %40angular/core}) and Go module paths are encoded the way
     * {@code ComponentCoordinate} will decode them.
     *
     * @return the PURL, or null when {@code purlType} is null or the pieces do not form a valid one
     */
    private static String build(String purlType, String rawName, String version) {
        if (purlType == null || rawName == null || rawName.isBlank()) {
            return null;
        }
        String name = rawName.trim();
        String namespace = null;

        if ("maven".equals(purlType)) {
            int colon = name.indexOf(':');
            if (colon <= 0 || colon == name.length() - 1) {
                // A Maven package with no groupId cannot be addressed in the ecosystem; a
                // name-only identity is more honest than half a coordinate.
                return null;
            }
            namespace = name.substring(0, colon);
            name = name.substring(colon + 1);
        } else if (name.startsWith("@")) {
            // npm scope: @angular/core -> namespace @angular, name core.
            int slash = name.indexOf('/');
            if (slash > 0) {
                namespace = name.substring(0, slash);
                name = name.substring(slash + 1);
            }
        } else {
            int lastSlash = name.lastIndexOf('/');
            if (lastSlash > 0) {
                // Go module paths and Composer vendors: everything before the last slash is namespace.
                namespace = name.substring(0, lastSlash);
                name = name.substring(lastSlash + 1);
            }
        }

        try {
            return new PackageURL(purlType, namespace, name,
                    version == null || version.isBlank() ? null : version.trim(), null, null).canonicalize();
        } catch (MalformedPackageURLException e) {
            log.debug("Could not synthesize a {} PURL for {}@{}: {}", purlType, rawName, version, e.getMessage());
            return null;
        }
    }

    private static String normalize(String value) {
        return value == null ? null : value.trim().toLowerCase(Locale.ROOT);
    }

}
