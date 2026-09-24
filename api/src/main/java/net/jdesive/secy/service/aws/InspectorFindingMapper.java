package net.jdesive.secy.service.aws;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.correlation.FixResolution;
import net.jdesive.secy.model.asset.ScannedPackage;
import net.jdesive.secy.model.component.NormalizedComponent;
import net.jdesive.secy.persistence.entity.AssetComponentSource;
import net.jdesive.secy.persistence.entity.FixSource;
import software.amazon.awssdk.services.inspector2.model.Finding;
import software.amazon.awssdk.services.inspector2.model.FixAvailable;
import software.amazon.awssdk.services.inspector2.model.PackageManager;
import software.amazon.awssdk.services.inspector2.model.PackageVulnerabilityDetails;
import software.amazon.awssdk.services.inspector2.model.VulnerablePackage;

import java.util.Locale;
import java.util.Map;

/**
 * Amazon Inspector v2's {@code Finding}/{@code VulnerablePackage} shapes → the same normalized model
 * {@code TrivyNormalizer}/{@code GrypeNormalizer} produce, so an AWS-Inspector-reported package
 * correlates exactly the way a Trivy- or Grype-reported one does — this is the whole point of
 * {@code ScannedPackage} wrapping a plain {@code NormalizedComponent}.
 *
 * <h2>{@code packageManager} → PURL type, and why OS packages get none</h2>
 *
 * <p>Same precedent {@code ScannerPurls} sets for Trivy/Grype: an ecosystem package manager (NPM,
 * PyPI's several spellings, Maven, …) gets a synthesized PURL so it takes the OSV-primary path; an OS
 * package ({@code PackageManager.OS} — apt/yum/apk-installed packages) gets none, because none of
 * those distro package managers is an OSV ecosystem and a distro-flavored PURL would only cost
 * identity stability (see {@code ScannerPurls}' class Javadoc) for zero correlation benefit — it takes
 * the CPE fallback either way.
 */
@Slf4j
final class InspectorFindingMapper {

    /**
     * {@code PackageManager} → PURL type. Only managers with an OSV/PURL counterpart appear;
     * {@code OS} and any manager not listed here (including a future
     * {@code UNKNOWN_TO_SDK_VERSION}) fall through to a PURL-less, name-only identity.
     */
    private static final Map<PackageManager, String> PURL_TYPES = Map.ofEntries(
            Map.entry(PackageManager.NPM, "npm"),
            Map.entry(PackageManager.NODEPKG, "npm"),
            Map.entry(PackageManager.YARN, "npm"),
            Map.entry(PackageManager.PIP, "pypi"),
            Map.entry(PackageManager.PIPENV, "pypi"),
            Map.entry(PackageManager.POETRY, "pypi"),
            Map.entry(PackageManager.PYTHONPKG, "pypi"),
            Map.entry(PackageManager.GOMOD, "golang"),
            Map.entry(PackageManager.GOBINARY, "golang"),
            Map.entry(PackageManager.JAR, "maven"),
            Map.entry(PackageManager.POM, "maven"),
            Map.entry(PackageManager.BUNDLER, "gem"),
            Map.entry(PackageManager.GEMSPEC, "gem"),
            Map.entry(PackageManager.NUGET, "nuget"),
            Map.entry(PackageManager.CARGO, "cargo"),
            Map.entry(PackageManager.COMPOSER, "composer"));

    private InspectorFindingMapper() {
    }

    /**
     * The CVE this finding is about, or null when it has none.
     *
     * <p>Inspector's package-vulnerability findings are keyed by {@code vulnerabilityId}, which is
     * overwhelmingly a CVE id already (unlike Grype's GHSA-first indexing); a finding whose id is not
     * CVE-shaped (or that carries no {@link PackageVulnerabilityDetails} at all — a code or network
     * reachability finding, which this connector does not ingest) is skipped, same policy
     * {@code TrivyNormalizer}/{@code GrypeNormalizer} apply for a non-CVE advisory id.
     */
    static String cveIdOf(Finding finding) {
        PackageVulnerabilityDetails details = finding == null ? null : finding.packageVulnerabilityDetails();
        String id = details == null ? null : trimToNull(details.vulnerabilityId());
        if (id == null || !id.regionMatches(true, 0, "CVE-", 0, 4)) {
            return null;
        }
        return id.toUpperCase(Locale.ROOT);
    }

    /** One Inspector-reported vulnerable package, as a {@link ScannedPackage} against {@code scanTarget}. */
    static ScannedPackage toScannedPackage(VulnerablePackage pkg, String scanTarget) {
        PackageManager manager = pkg.packageManager();
        String purl = manager == PackageManager.OS ? null : buildPurl(manager, pkg.name(), pkg.version());

        NormalizedComponent component = NormalizedComponent.builder()
                .name(pkg.name())
                .version(pkg.version())
                .purl(purl)
                .type(pkg.packageManagerAsString())
                .build();

        return new ScannedPackage(component, AssetComponentSource.AWS_INSPECTOR, scanTarget,
                trimToNull(pkg.filePath()), null);
    }

    /**
     * Inspector's fix signal for one vulnerable package.
     *
     * <table border="1">
     *   <caption>Inspector fix data to FixResolution</caption>
     *   <tr><th>input</th><th>result</th></tr>
     *   <tr><td>{@code vulnerablePackage.fixedInVersion} present</td><td>{@code FIXED} at that version — true regardless of the finding's overall {@code fixAvailable}, since {@code PARTIAL} means exactly "fixed for some packages, not others" and a stated version is this package's own answer</td></tr>
     *   <tr><td>no version, {@code fixAvailable == NO}</td><td>{@code NO_FIX} — a positive claim no fix exists</td></tr>
     *   <tr><td>no version, {@code fixAvailable} is {@code YES}/{@code PARTIAL}/absent/unknown</td><td>{@code UNKNOWN} — Inspector said something about the finding but not a usable version for this package</td></tr>
     * </table>
     */
    static FixResolution fixOf(FixAvailable fixAvailable, String fixedInVersion) {
        String version = trimToNull(fixedInVersion);
        if (version != null) {
            return FixResolution.fixed(version, FixSource.SCANNER);
        }
        if (fixAvailable == FixAvailable.NO) {
            return FixResolution.noFix(FixSource.SCANNER);
        }
        return FixResolution.unknown(FixSource.SCANNER);
    }

    /**
     * Assemble a PURL through {@link PackageURL}, the same way {@code ScannerPurls.build} does for
     * Trivy/Grype — namespace split out of a Maven {@code groupId:artifactId} name or an npm
     * {@code @scope/name}, everything else namespace-less.
     *
     * @return the PURL, or null when {@code manager} has no PURL counterpart or the pieces do not
     *         form a valid one
     */
    private static String buildPurl(PackageManager manager, String rawName, String version) {
        String purlType = manager == null ? null : PURL_TYPES.get(manager);
        if (purlType == null || rawName == null || rawName.isBlank()) {
            return null;
        }
        String name = rawName.trim();
        String namespace = null;

        if ("maven".equals(purlType)) {
            int colon = name.indexOf(':');
            if (colon <= 0 || colon == name.length() - 1) {
                // A Maven package with no groupId cannot be addressed in the ecosystem; a name-only
                // identity is more honest than half a coordinate.
                return null;
            }
            namespace = name.substring(0, colon);
            name = name.substring(colon + 1);
        } else if (name.startsWith("@")) {
            int slash = name.indexOf('/');
            if (slash > 0) {
                namespace = name.substring(0, slash);
                name = name.substring(slash + 1);
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

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

}
