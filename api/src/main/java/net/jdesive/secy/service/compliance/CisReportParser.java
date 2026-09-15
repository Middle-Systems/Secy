package net.jdesive.secy.service.compliance;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.correlation.FixResolution;
import net.jdesive.secy.model.asset.ScannedPackage;
import net.jdesive.secy.model.asset.ScannerFinding;
import net.jdesive.secy.model.compliance.NormalizedComplianceReport;
import net.jdesive.secy.model.compliance.NormalizedControl;
import net.jdesive.secy.model.compliance.NormalizedMisconfiguration;
import net.jdesive.secy.model.component.NormalizedComponent;
import net.jdesive.secy.model.docker.CISReport;
import net.jdesive.secy.model.docker.CISReportMisconfig;
import net.jdesive.secy.model.docker.CISReportResult;
import net.jdesive.secy.model.docker.CISReportResultResult;
import net.jdesive.secy.model.docker.CISReportVulnerability;
import net.jdesive.secy.persistence.entity.AssetComponentSource;
import net.jdesive.secy.persistence.entity.ComplianceStatus;
import net.jdesive.secy.persistence.entity.FixSource;
import net.jdesive.secy.service.asset.ScannerPurls;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Validates an uploaded {@code trivy --compliance} document and parses it into
 * {@link NormalizedComplianceReport}.
 *
 * <p>The {@code AssetScanParser} of the compliance path, and deliberately the same contract:
 * parsing is <b>synchronous</b>, ahead of the job queue, so a document that can never succeed gets a
 * plain {@code 400} with nothing stored and nothing queued.
 *
 * <h2>Why this is not {@code TrivyNormalizer}</h2>
 *
 * <p>The two documents are different shapes with a shared leaf. A compliance report is
 * {@code ID/Title/Results[] (control) → results[] (target) → {misconfigurations[], vulnerabilities[]}};
 * an image report is {@code ArtifactName/Results[] (target) → Vulnerabilities[]}. Only the innermost
 * vulnerability object is common, and it is common because it genuinely is the same object.
 *
 * <p>So the <em>wire</em> models stay separate — bending {@code model/trivy} to also mean "control"
 * would make both unreadable — while the <em>output</em> is identical: the same
 * {@link ScannedPackage}/{@link ScannerFinding} records, following the same rules
 * ({@code os-pkgs} get no PURL, a non-CVE id is dropped, {@code FixedVersion} becomes a
 * {@code SCANNER} fix). Everything downstream of this class cannot tell the two apart, which is the
 * entire point of Phase 5.
 */
@Slf4j
@Service
public class CisReportParser {

    private final ObjectMapper objectMapper;

    public CisReportParser(ObjectMapper objectMapper) {
        // Same ingest-hardening reasoning as AssetScanParser: Trivy adds report fields every
        // release, and a report Secy could read 99% of must not be rejected because one new key
        // appeared.
        this.objectMapper = objectMapper.copy().disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
    }

    /**
     * @throws UnsupportedComplianceReportException when the body is not a JSON object, or is not a
     *                                              Trivy compliance report
     */
    public NormalizedComplianceReport parse(JsonNode root) {
        if (root == null || !root.isObject()) {
            throw new UnsupportedComplianceReportException(
                    "Request body must be a JSON object containing a Trivy compliance report.");
        }
        if (looksLikeImageScan(root)) {
            throw new UnsupportedComplianceReportException(
                    "This looks like a `trivy image` vulnerability report, not a compliance report. "
                            + "Post it to /assets/scan/trivy.");
        }
        if (!looksLikeCompliance(root)) {
            throw new UnsupportedComplianceReportException(
                    "Not a Trivy compliance report: expected a top-level 'Results' array alongside an "
                            + "'ID' and 'Title', as produced by `trivy ... --compliance <spec> -f json`.");
        }

        CISReport report;
        try {
            report = objectMapper.treeToValue(root, CISReport.class);
        } catch (Exception e) {
            throw new UnsupportedComplianceReportException(
                    "Document looks like a compliance report but could not be read as one: " + e.getMessage(), e);
        }
        return normalize(report);
    }

    /* ------------------------------------------------------------------ */
    /* Normalization                                                      */
    /* ------------------------------------------------------------------ */

    private NormalizedComplianceReport normalize(CISReport report) {
        List<NormalizedControl> controls = new ArrayList<>();
        // Keyed by identity so one package appearing under two controls/targets becomes one
        // component, the way CorrelationService will key its alerts.
        Map<String, ScannedPackage> packages = new LinkedHashMap<>();
        List<ScannerFinding> findings = new ArrayList<>();
        int skipped = 0;
        String artifactName = trimToNull(report.getArtifactName());

        for (CISReportResult control : nullSafe(report.getResults())) {
            if (control == null) {
                continue;
            }
            List<NormalizedMisconfiguration> checks = new ArrayList<>();

            for (CISReportResultResult target : nullSafe(control.getResults())) {
                if (target == null) {
                    continue;
                }
                if (artifactName == null) {
                    artifactName = trimToNull(target.getTarget());
                }

                for (CISReportMisconfig misconfig : nullSafe(target.getMisconfigurations())) {
                    if (misconfig != null) {
                        checks.add(toMisconfiguration(misconfig, target));
                    }
                }

                for (CISReportVulnerability vulnerability : nullSafe(target.getVulnerabilities())) {
                    if (vulnerability == null || isBlank(vulnerability.getPkgName())) {
                        skipped++;
                        continue;
                    }
                    String cveId = cveIdOf(vulnerability.getVulnerabilityId());
                    if (cveId == null) {
                        // A distro-only advisory id with no CVE. The funnel is CVE-keyed end to end,
                        // so an alert here could never be enriched, sorted or explained. Same policy
                        // TrivyNormalizer applies.
                        log.debug("Compliance finding {} on {} is not a CVE; skipping",
                                vulnerability.getVulnerabilityId(), vulnerability.getPkgName());
                        skipped++;
                        continue;
                    }
                    ScannedPackage scanned = toPackage(target, vulnerability);
                    if (scanned.identityKey() == null) {
                        skipped++;
                        continue;
                    }
                    ScannedPackage existing = packages.putIfAbsent(scanned.identityKey(), scanned);
                    findings.add(new ScannerFinding(existing == null ? scanned : existing, cveId,
                            fixOf(vulnerability.getFixedVersion())));
                }
            }

            controls.add(new NormalizedControl(
                    trimToNull(control.getId()),
                    trimToNull(control.getName()),
                    trimToNull(control.getDescription()),
                    trimToNull(control.getSeverity()),
                    ComplianceStatus.rollUp(checks.stream().map(NormalizedMisconfiguration::status).toList()),
                    checks));
        }

        log.info("Parsed compliance report {} ({}): {} controls, {} vulnerable packages, {} findings ({} skipped)",
                report.getId(), artifactName, controls.size(), packages.size(), findings.size(), skipped);

        return new NormalizedComplianceReport(
                trimToNull(report.getId()),
                trimToNull(report.getTitle()),
                trimToNull(report.getDescription()),
                trimToNull(report.getVersion()),
                artifactName,
                nullSafe(report.getRelatedResources()).stream().filter(url -> !isBlank(url)).toList(),
                controls,
                List.copyOf(packages.values()),
                findings,
                skipped);
    }

    private static NormalizedMisconfiguration toMisconfiguration(CISReportMisconfig misconfig,
                                                                 CISReportResultResult target) {
        return new NormalizedMisconfiguration(
                trimToNull(misconfig.getType()),
                trimToNull(misconfig.getId()),
                trimToNull(misconfig.getAvdId()),
                trimToNull(misconfig.getTitle()),
                trimToNull(misconfig.getDescription()),
                trimToNull(misconfig.getMessage()),
                trimToNull(misconfig.getResolution()),
                trimToNull(misconfig.getSeverity()),
                trimToNull(misconfig.getPrimaryUrl()),
                ComplianceStatus.ofFinding(misconfig.getStatus()),
                trimToNull(target.getTarget()),
                nullSafe(misconfig.getReferences()).stream().filter(url -> !isBlank(url)).toList());
    }

    /**
     * The vulnerability, as a package on the audited asset.
     *
     * <p>Identical rules to {@code TrivyNormalizer.toPackage}: an {@code os-pkgs} target's packages
     * carry no PURL (so they take the CPE fallback, which is the path NVD is canonical for), a
     * {@code lang-pkgs} target's do (so they take the OSV-primary path, exactly like an SBOM
     * component), and Trivy's own PURL always beats a synthesized one.
     */
    private static ScannedPackage toPackage(CISReportResultResult target, CISReportVulnerability vulnerability) {
        String purl = isOsPackages(target)
                ? null
                : firstNonBlank(vulnerability.purl(), ScannerPurls.forTrivy(
                        target.getType(), vulnerability.getPkgName(), vulnerability.getInstalledVersion()));

        NormalizedComponent component = NormalizedComponent.builder()
                .name(vulnerability.getPkgName())
                .version(vulnerability.getInstalledVersion())
                .purl(purl)
                .type(target.getType())
                .build();

        return new ScannedPackage(component, AssetComponentSource.TRIVY, trimToNull(target.getTarget()),
                trimToNull(vulnerability.getPkgPath()), trimToNull(vulnerability.layerDiffId()));
    }

    /**
     * {@code Class: os-pkgs}, or a {@code Type} that names a distro.
     *
     * <p>The second half matters here and not on the image path: a compliance report's nested results
     * do not always carry {@code Class}, and mis-classifying an OS package as a language package
     * would synthesize a PURL for it and change which corpus it is matched against.
     */
    private static boolean isOsPackages(CISReportResultResult target) {
        if ("os-pkgs".equalsIgnoreCase(trimToNull(target.getClassType()))) {
            return true;
        }
        return ScannerPurls.isOsPackageType(target.getType());
    }

    /** Uppercased so the correlation key and the {@code vulnerabilities} lookup agree. */
    private static String cveIdOf(String vulnerabilityId) {
        String id = trimToNull(vulnerabilityId);
        if (id == null || !id.regionMatches(true, 0, "CVE-", 0, 4)) {
            return null;
        }
        return id.toUpperCase(Locale.ROOT);
    }

    /**
     * Trivy has no "no fix exists" signal distinct from "no data", so an absent {@code FixedVersion}
     * is {@code null} — "nothing to say" — rather than {@code NO_FIX}, leaving correlation free to
     * supply a fix OSV knows about.
     */
    private static FixResolution fixOf(String fixedVersion) {
        String fixed = trimToNull(fixedVersion);
        return fixed == null ? null : FixResolution.fixed(fixed, FixSource.SCANNER);
    }

    /* ------------------------------------------------------------------ */
    /* Shape detection                                                    */
    /* ------------------------------------------------------------------ */

    /**
     * {@code Results} plus the benchmark's identity. An image report also has {@code Results}, with a
     * completely different element shape, so {@code ID} + {@code Title} is what keeps the two apart —
     * the mirror image of the check {@code AssetScanParser} makes in the other direction.
     */
    private static boolean looksLikeCompliance(JsonNode root) {
        return root.path("Results").isArray()
                && root.path("ID").isTextual()
                && root.path("Title").isTextual();
    }

    private static boolean looksLikeImageScan(JsonNode root) {
        return root.path("Results").isArray()
                && (root.path("SchemaVersion").isNumber() || root.path("ArtifactType").isTextual())
                && !root.path("ID").isTextual();
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                            */
    /* ------------------------------------------------------------------ */

    private static <T> List<T> nullSafe(List<T> values) {
        return values == null ? List.of() : values;
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
