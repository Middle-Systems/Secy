package net.jdesive.secy.service.asset;

import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.correlation.FixResolution;
import net.jdesive.secy.model.asset.NormalizedScan;
import net.jdesive.secy.model.asset.ScanFormat;
import net.jdesive.secy.model.asset.ScannedPackage;
import net.jdesive.secy.model.asset.ScannerFinding;
import net.jdesive.secy.model.component.NormalizedComponent;
import net.jdesive.secy.model.trivy.TrivyReport;
import net.jdesive.secy.model.trivy.TrivyResult;
import net.jdesive.secy.model.trivy.TrivyVulnerability;
import net.jdesive.secy.persistence.entity.AssetComponentSource;
import net.jdesive.secy.persistence.entity.FixSource;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * {@code trivy image -f json} → the normalized model.
 *
 * <h2>What a scanner report is, and is not</h2>
 *
 * <p>A Trivy report lists <b>packages it found a vulnerability in</b>, not the image's full package
 * inventory. So the packages this produces are the vulnerable subset, and an {@code AssetComponent}
 * row existing is not a claim that the asset contains nothing else. (Trivy can be asked for a full
 * SBOM instead, and that path already exists: upload the SBOM against a product.)
 *
 * <h2>Class decides the coordinate space</h2>
 *
 * <ul>
 *   <li>{@code Class: lang-pkgs} — {@code Type} names an ecosystem ({@code npm}, {@code gomod},
 *       {@code jar}, …), so the package gets a PURL and takes the OSV-primary path, exactly like an
 *       SBOM component.</li>
 *   <li>{@code Class: os-pkgs} — {@code Type} names a distro. No PURL (see {@link ScannerPurls}), so
 *       the package takes the CPE fallback, which is the path NVD is actually canonical for.</li>
 * </ul>
 */
@Slf4j
@Component
public class TrivyNormalizer {

    public NormalizedScan normalize(TrivyReport report) {
        // Keyed by identity so one package appearing under two targets becomes one component, the
        // way CorrelationService will key its alerts.
        Map<String, ScannedPackage> packages = new LinkedHashMap<>();
        List<ScannerFinding> findings = new ArrayList<>();
        int skipped = 0;

        for (TrivyResult result : report.results()) {
            for (TrivyVulnerability vulnerability : result.vulnerabilities()) {
                if (vulnerability == null || isBlank(vulnerability.pkgName())) {
                    skipped++;
                    continue;
                }

                String cveId = cveIdOf(vulnerability);
                if (cveId == null) {
                    // A distro-only advisory id (DLA-3401-1, ALAS-2023-…) with no CVE. The funnel is
                    // CVE-keyed end to end — KEV, EPSS, the CVE browser — so an alert here could
                    // never be enriched, sorted or explained. Same policy Phase 2 set for GHSA-only
                    // OSV advisories.
                    log.debug("Trivy finding {} on {} is not a CVE; skipping",
                            vulnerability.vulnerabilityId(), vulnerability.pkgName());
                    skipped++;
                    continue;
                }

                ScannedPackage scanned = toPackage(result, vulnerability);
                if (scanned.identityKey() == null) {
                    skipped++;
                    continue;
                }
                ScannedPackage existing = packages.putIfAbsent(scanned.identityKey(), scanned);
                findings.add(new ScannerFinding(existing == null ? scanned : existing, cveId,
                        fixOf(vulnerability)));
            }
        }

        log.info("Parsed Trivy report for {}: {} vulnerable packages, {} findings ({} skipped)",
                report.artifactName(), packages.size(), findings.size(), skipped);
        return new NormalizedScan(ScanFormat.TRIVY, trimToNull(report.artifactName()),
                List.copyOf(packages.values()), findings, skipped);
    }

    /**
     * The finding's CVE, or null when it has none.
     *
     * <p>Trivy carries CWE ids and vendor severities but no alias list, so unlike Grype there is
     * nothing here to resolve a distro id through. Uppercased so the correlation key and the
     * {@code vulnerabilities} lookup agree.
     */
    private static String cveIdOf(TrivyVulnerability vulnerability) {
        String id = trimToNull(vulnerability.vulnerabilityId());
        if (id == null || !id.regionMatches(true, 0, "CVE-", 0, 4)) {
            return null;
        }
        return id.toUpperCase(Locale.ROOT);
    }

    private static ScannedPackage toPackage(TrivyResult result, TrivyVulnerability vulnerability) {
        String purl = result.isOsPackages()
                ? null
                : firstNonBlank(vulnerability.purl(), ScannerPurls.forTrivy(
                        result.type(), vulnerability.pkgName(), vulnerability.installedVersion()));

        NormalizedComponent component = NormalizedComponent.builder()
                .name(vulnerability.pkgName())
                .version(vulnerability.installedVersion())
                .purl(purl)
                // Not a CycloneDX component type — the scanner's own ecosystem label, which is the
                // closest thing to provenance the report carries for a package.
                .type(result.type())
                .build();

        return new ScannedPackage(component, AssetComponentSource.TRIVY, result.target(),
                trimToNull(vulnerability.pkgPath()),
                vulnerability.layer() == null ? null : trimToNull(vulnerability.layer().diffId()));
    }

    /**
     * What Trivy said about a fix.
     *
     * <p>{@code FixedVersion} present → {@code FIXED} at that version, source {@code SCANNER}. Trivy
     * has no "no fix exists" signal distinct from "no data", so an absent one is {@code null} —
     * "nothing to say" — rather than {@code NO_FIX}, which is a positive claim only OSV and Grype
     * make. Correlation is then free to supply a fix OSV knows about.
     */
    private static FixResolution fixOf(TrivyVulnerability vulnerability) {
        String fixed = trimToNull(vulnerability.fixedVersion());
        return fixed == null ? null : FixResolution.fixed(fixed, FixSource.SCANNER);
    }

    private static String firstNonBlank(String a, String b) {
        String first = trimToNull(a);
        return first != null ? first : trimToNull(b);
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

}
