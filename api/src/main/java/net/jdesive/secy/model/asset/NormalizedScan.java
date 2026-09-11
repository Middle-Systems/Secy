package net.jdesive.secy.model.asset;

import java.util.List;

/**
 * A whole scanner report, normalized — the only thing {@code AssetService} accepts.
 *
 * <p>The asset analogue of {@code NormalizedSbom}, and deliberately the same idea: the ingest
 * pipeline never learns whether Trivy or Grype produced the document, exactly as it never learns
 * whether an SBOM was CycloneDX or SPDX.
 *
 * @param format          which scanner produced it
 * @param artifactName    what the scanner says it scanned ({@code alpine:3.18}, a path, …), or null.
 *                        Used as the asset name when the caller did not supply one.
 * @param packages        every distinct package the scan reported, deduplicated by identity. A
 *                        scanner only reports packages it found a vulnerability in, so this is the
 *                        vulnerable subset of the asset's inventory, not the whole of it.
 * @param findings        every (package, CVE) statement the scanner made
 * @param skippedFindings findings dropped because their id was neither a CVE nor resolvable to one,
 *                        or because they named no package. Reported on the job so the number is
 *                        visible rather than silently swallowed.
 */
public record NormalizedScan(ScanFormat format,
                             String artifactName,
                             List<ScannedPackage> packages,
                             List<ScannerFinding> findings,
                             int skippedFindings) {

    public NormalizedScan {
        packages = packages == null ? List.of() : List.copyOf(packages);
        findings = findings == null ? List.of() : List.copyOf(findings);
    }

}
