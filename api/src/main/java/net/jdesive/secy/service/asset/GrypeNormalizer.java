package net.jdesive.secy.service.asset;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.correlation.FixResolution;
import net.jdesive.secy.model.asset.NormalizedScan;
import net.jdesive.secy.model.asset.ScanFormat;
import net.jdesive.secy.model.asset.ScannedPackage;
import net.jdesive.secy.model.asset.ScannerFinding;
import net.jdesive.secy.model.component.NormalizedComponent;
import net.jdesive.secy.model.grype.GrypeArtifact;
import net.jdesive.secy.model.grype.GrypeMatch;
import net.jdesive.secy.model.grype.GrypeReport;
import net.jdesive.secy.model.grype.GrypeVulnerability;
import net.jdesive.secy.persistence.OsvAdvisoryRepository;
import net.jdesive.secy.persistence.entity.AssetComponentSource;
import net.jdesive.secy.persistence.entity.FixSource;
import net.jdesive.secy.persistence.entity.OsvAdvisory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * {@code grype -o json} → the normalized model.
 *
 * <h2>Differences from the Trivy path that actually matter</h2>
 *
 * <ol>
 *   <li><b>Grype emits a PURL.</b> Syft built it from the package metadata, so it beats anything
 *       {@link ScannerPurls} could reconstruct from a name and a type label, and it is used verbatim
 *       whenever present — except for OS packages, where it is dropped for the identity-stability
 *       reason {@code ScannerPurls} documents.</li>
 *   <li><b>Grype indexes GitHub advisories under their GHSA id.</b> {@code vulnerability.id} is
 *       therefore often {@code GHSA-…}, with the CVE sitting in {@code relatedVulnerabilities[]}.
 *       That list is consulted first and the OSV mirror's alias set second; a match that resolves to
 *       no CVE at all is skipped, the policy Phase 2 fixed for GHSA-only OSV advisories.</li>
 *   <li><b>Grype states a fix <em>state</em>, not just a version.</b> {@code wont-fix} and
 *       {@code not-fixed} are positive claims that no fixed release exists, which Trivy cannot
 *       express — they map to {@code NO_FIX}, not to "unknown".</li>
 * </ol>
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class GrypeNormalizer {

    private final OsvAdvisoryRepository osvAdvisoryRepository;

    public NormalizedScan normalize(GrypeReport report) {
        Map<String, ScannedPackage> packages = new LinkedHashMap<>();
        List<ScannerFinding> findings = new ArrayList<>();
        int skipped = 0;

        for (GrypeMatch match : report.matches()) {
            GrypeArtifact artifact = match == null ? null : match.artifact();
            GrypeVulnerability vulnerability = match == null ? null : match.vulnerability();
            if (artifact == null || vulnerability == null || isBlank(artifact.name())) {
                skipped++;
                continue;
            }

            String cveId = cveIdOf(match);
            if (cveId == null) {
                log.debug("Grype match {} on {} resolves to no CVE; skipping",
                        vulnerability.id(), artifact.name());
                skipped++;
                continue;
            }

            ScannedPackage scanned = toPackage(artifact);
            if (scanned.identityKey() == null) {
                skipped++;
                continue;
            }
            ScannedPackage existing = packages.putIfAbsent(scanned.identityKey(), scanned);
            findings.add(new ScannerFinding(existing == null ? scanned : existing, cveId,
                    fixOf(vulnerability)));
        }

        String artifactName = targetName(report);
        log.info("Parsed Grype report for {}: {} vulnerable packages, {} findings ({} skipped)",
                artifactName, packages.size(), findings.size(), skipped);
        return new NormalizedScan(ScanFormat.GRYPE, artifactName, List.copyOf(packages.values()),
                findings, skipped);
    }

    /* ------------------------------------------------------------------ */
    /* CVE resolution                                                     */
    /* ------------------------------------------------------------------ */

    /**
     * The CVE this match is about, or null when it has none.
     *
     * <p>Three attempts, cheapest first: the id itself, the {@code relatedVulnerabilities} Grype
     * shipped in the same document, then the OSV mirror's alias set for the advisory id. The last one
     * is a database round trip and only runs for a GHSA that Grype did not already annotate.
     */
    private String cveIdOf(GrypeMatch match) {
        GrypeVulnerability vulnerability = match.vulnerability();
        if (vulnerability.isCve()) {
            return upper(vulnerability.id());
        }

        for (GrypeVulnerability related : match.relatedVulnerabilities()) {
            if (related != null && related.isCve()) {
                return upper(related.id());
            }
        }

        String id = trimToNull(vulnerability.id());
        if (id == null) {
            return null;
        }
        for (OsvAdvisory advisory : osvAdvisoryRepository.findByOsvId(id)) {
            String alias = advisory.cveAlias();
            if (alias != null) {
                return upper(alias);
            }
        }
        return null;
    }

    /* ------------------------------------------------------------------ */
    /* Mapping                                                            */
    /* ------------------------------------------------------------------ */

    private static ScannedPackage toPackage(GrypeArtifact artifact) {
        boolean osPackage = ScannerPurls.isOsPackageType(artifact.type());
        String purl = osPackage
                ? null
                : firstNonBlank(artifact.purl(),
                        ScannerPurls.forGrype(artifact.type(), artifact.name(), artifact.version()));

        NormalizedComponent component = NormalizedComponent.builder()
                .name(artifact.name())
                .version(artifact.version())
                .purl(purl)
                .type(artifact.type())
                .build();

        GrypeArtifact.GrypeLocation location = artifact.primaryLocation();
        return new ScannedPackage(component, AssetComponentSource.GRYPE, null,
                location == null ? null : trimToNull(location.path()),
                location == null ? null : trimToNull(location.layerID()));
    }

    /**
     * Grype's fix block, mapped onto {@code FixState}.
     *
     * <table border="1">
     *   <caption>Grype fix.state to FixState</caption>
     *   <tr><th>{@code fix.state}</th><th>result</th></tr>
     *   <tr><td>{@code fixed}</td><td>{@code FIXED} at {@code fix.versions}, or {@code UNKNOWN} when the list is empty</td></tr>
     *   <tr><td>{@code wont-fix}</td><td>{@code NO_FIX} — the vendor has said it will not ship one</td></tr>
     *   <tr><td>{@code not-fixed}</td><td>{@code NO_FIX} — no fixed release exists yet. Both are positive claims that upgrading is not currently an option, which is the decision an operator makes on this field; the reason they differ is history, not action.</td></tr>
     *   <tr><td>{@code unknown} / absent</td><td>{@code null} — nothing said, so correlation may fill it in</td></tr>
     * </table>
     */
    private static FixResolution fixOf(GrypeVulnerability vulnerability) {
        String state = vulnerability.fixState();
        if (state == null) {
            return null;
        }
        return switch (state) {
            case "fixed" -> vulnerability.fix().versions().isEmpty()
                    ? null
                    : FixResolution.fixed(vulnerability.fix().versions(), FixSource.SCANNER);
            case "wont-fix", "not-fixed" -> FixResolution.noFix(FixSource.SCANNER);
            default -> null;
        };
    }

    /**
     * What Grype scanned. {@code source.target} is a bare string for a directory scan and an object
     * carrying {@code userInput} for an image, so both shapes are read rather than assumed.
     */
    private static String targetName(GrypeReport report) {
        if (report.source() == null || report.source().target() == null) {
            return null;
        }
        JsonNode target = report.source().target();
        if (target.isTextual()) {
            return trimToNull(target.asText());
        }
        JsonNode userInput = target.get("userInput");
        return userInput != null && userInput.isTextual() ? trimToNull(userInput.asText()) : null;
    }

    private static String upper(String value) {
        String trimmed = trimToNull(value);
        return trimmed == null ? null : trimmed.toUpperCase(Locale.ROOT);
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
