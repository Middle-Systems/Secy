package net.jdesive.secy.model.asset;

import net.jdesive.secy.correlation.FixResolution;

/**
 * One "this scanner says this package has this CVE" statement, normalized away from Trivy's and
 * Grype's very different shapes.
 *
 * <p>This is the asset-side counterpart of {@code CorrelationMatch}: what the scanner asserted,
 * before Secy has agreed or disagreed. Per the roadmap a scanner-reported CVE becomes an alert
 * immediately — Secy does not wait for OSV or NVD to reproduce the finding — but it still routes
 * through {@code EnrichmentService} for the KEV/EPSS/exploit-maturity funnel, and correlation runs
 * alongside it so an OSV fix version can improve on a scanner that supplied none.
 *
 * @param pkg   the affected package
 * @param cveId the resolved CVE id, uppercased. A finding whose id could not be resolved to a CVE
 *              never becomes one of these — the funnel is CVE-keyed end to end.
 * @param fix   what the scanner said about a fix, always with {@code source = SCANNER}. Null when it
 *              said nothing at all, which is different from saying "no fix exists".
 */
public record ScannerFinding(ScannedPackage pkg, String cveId, FixResolution fix) {
}
