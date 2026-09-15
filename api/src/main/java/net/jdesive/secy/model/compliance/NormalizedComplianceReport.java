package net.jdesive.secy.model.compliance;

import net.jdesive.secy.model.asset.ScannedPackage;
import net.jdesive.secy.model.asset.ScannerFinding;

import java.util.List;

/**
 * A whole {@code trivy --compliance} document, normalized — the only thing {@code ComplianceService}
 * accepts.
 *
 * <h2>Two halves, on purpose</h2>
 *
 * <p>A compliance report says two unrelated things. The {@link #controls} half is benchmark
 * verdicts: configuration rules with a pass/fail/skip and remediation text. The
 * {@link #packages}/{@link #findings} half is ordinary vulnerability findings, in exactly the shape
 * {@code trivy image} produces — so it is normalized into the <em>same</em>
 * {@link ScannedPackage}/{@link ScannerFinding} records the Phase 4 asset pipeline consumes, and
 * from here on it is indistinguishable from an asset scan.
 *
 * @param benchmarkId      the benchmark's own {@code ID}, e.g. {@code docker-cis-1.6.0}
 * @param artifactName     what the document says it audited, or null — the compliance format has no
 *                         guaranteed identity field, so the upload's {@code name} parameter takes
 *                         precedence and is required when this is null
 * @param relatedResources benchmark reference URLs
 * @param controls         the benchmark's controls, in document order, each with its checks
 * @param packages         distinct vulnerable packages from the vulnerability half
 * @param findings         every {@code (package, CVE)} statement the vulnerability half made
 * @param skippedFindings  vulnerability entries dropped for naming no package or no CVE
 */
public record NormalizedComplianceReport(String benchmarkId,
                                         String title,
                                         String description,
                                         String version,
                                         String artifactName,
                                         List<String> relatedResources,
                                         List<NormalizedControl> controls,
                                         List<ScannedPackage> packages,
                                         List<ScannerFinding> findings,
                                         int skippedFindings) {

    public NormalizedComplianceReport {
        relatedResources = relatedResources == null ? List.of() : List.copyOf(relatedResources);
        controls = controls == null ? List.of() : List.copyOf(controls);
        packages = packages == null ? List.of() : List.copyOf(packages);
        findings = findings == null ? List.of() : List.copyOf(findings);
    }

}
