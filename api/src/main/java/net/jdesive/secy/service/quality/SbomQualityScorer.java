package net.jdesive.secy.service.quality;

import net.jdesive.secy.model.cbom.CryptoAssets;
import net.jdesive.secy.model.component.NormalizedComponent;
import net.jdesive.secy.model.component.NormalizedSbom;
import net.jdesive.secy.persistence.entity.SbomQualityScore;

import java.util.ArrayList;
import java.util.List;

/**
 * M1h's NTIA minimum-elements completeness score (ROADMAP.md — "M1h — SBOM quality scoring"): a
 * pure function of one {@link NormalizedSbom}, computed inline at ingest (same "self-contained, so
 * inline" reasoning as M1c's Pass A / M1g's crypto classification — see
 * {@code net.jdesive.secy.service.SBOMService#ingestDocument}). No Spring/JPA, same style as
 * {@code QuantumVulnerabilityClassifier}.
 *
 * <h2>Scored population</h2>
 *
 * <p>{@code doc.components()} (the root is never included there) minus every crypto-asset
 * component ({@link CryptoAssets#isCryptoAsset}) — a crypto asset has no meaningful "supplier" or
 * "dependency relationship" in the NTIA sense, and a document made entirely of them (a standalone
 * CBOM) is not what NTIA completeness was designed to grade. If the population is empty (zero
 * components, or every component is a crypto asset), this returns {@code null} — "not scored", not
 * a score of zero.
 *
 * <h2>The seven elements</h2>
 *
 * <p>Five are per-component (n = population size), each with its own coverage percentage,
 * {@code floor(100 * count / n)}:
 * <ul>
 *   <li>{@code SUPPLIER} — {@link NormalizedComponent#supplier()} non-null</li>
 *   <li>{@code COMPONENT_NAME} — {@link NormalizedComponent#name()} non-null</li>
 *   <li>{@code COMPONENT_VERSION} — {@link NormalizedComponent#version()} non-null</li>
 *   <li>{@code UNIQUE_IDENTIFIER} — a PURL, or a declared CPE/SWID identifier, or a declared hash</li>
 *   <li>{@code DEPENDENCY_RELATIONSHIP} — the component has a bom-ref AND that bom-ref appears in
 *       {@link NormalizedSbom#dependencyRelationshipRefs()} (exact, case-sensitive match). A
 *       component with no bom-ref automatically fails this test — deliberately presence-only
 *       even after M1l's real directed graph shipped (ROADMAP.md, M1l — "Dependency graph
 *       preserved"): {@code dependencyRelationshipRefs} stays exactly as M1h defined it (all 15
 *       SPDX relationship types, the explicit {@code {ref:X, dependsOn:[]}} assertion), and this
 *       NTIA check was never meant to validate the real dependency graph — see {@link
 *       net.jdesive.secy.model.component.DependencyGraphAnalyzer} for that</li>
 * </ul>
 *
 * <p>Two are document-level, all-or-nothing (0 or 1, doubling as "coverage" for the formula below):
 * <ul>
 *   <li>{@code AUTHOR} — {@link NormalizedSbom#authors()} non-empty. Tools never count.</li>
 *   <li>{@code TIMESTAMP} — {@link NormalizedSbom#documentTimestamp()} non-null. The document's own
 *       declared timestamp only — never {@code sbom.uploadDate}.</li>
 * </ul>
 *
 * <h2>Formula</h2>
 *
 * <p>Equal weight across all seven elements, exact integer arithmetic, rounded down:
 *
 * <pre>
 * score = floor( 100 * (Σ_{5 component elements} count_e + n·hasAuthor + n·hasTimestamp) / (7 · n) )
 * </pre>
 *
 * <p>Rounding down guarantees a 100 means fully complete — 299 suppliers out of 300 components
 * rounds to 99, never up to 100. A finding is raised (see {@code SbomQualityFindingService}) when
 * {@code score < FINDING_THRESHOLD}, strictly — exactly 70 raises nothing, 69 does. No severity
 * bands; this is a binary "finding exists or not" (M1i may rank by distance below threshold later,
 * using the {@code scoreThreshold} stored alongside a finding).
 *
 * <h2>Worked examples (verified against this implementation)</h2>
 *
 * <ul>
 *   <li>Fully compliant document (every element present for every component) → 100</li>
 *   <li>Typical {@code syft} output — name/version/PURL/timestamp/dependencies present, no
 *       supplier/author — → 5/7 elements fully covered ≈ floor(500/7) = 71 → no finding</li>
 *   <li>Same, minus dependency relationships → 4/7 ≈ floor(400/7) = 57 → finding</li>
 *   <li>Sparse document — 3 components, all with name+version, one with a PURL, nothing else → per
 *       component: name 100%, version 100%, uniqueId 33%, supplier 0%, dependency 0%, no
 *       author/timestamp → floor(100 · (300+300+100+0+0+0+0) / (7·3)) = floor(70000/2100) = 33 →
 *       finding</li>
 * </ul>
 */
public final class SbomQualityScorer {

    /**
     * A finding is raised when the score is strictly below this. A constant, not a
     * {@code @ConfigurationProperties} field, because the test {@code application.properties}
     * <b>replaces</b> the main one rather than merging with it — a property here would need
     * restating there too. Future expansion (tenant-configurable scoring) may make this
     * tenant-configurable later, the same way M1i's {@code ScoringWeightsProvider} is the seam for
     * per-tenant risk-scoring weights.
     */
    public static final int FINDING_THRESHOLD = 70;

    private SbomQualityScorer() {
    }

    /**
     * Scores {@code doc} against the NTIA minimum elements, or returns {@code null} when the scored
     * population is empty (no non-crypto components).
     */
    public static SbomQualityScore score(NormalizedSbom doc) {
        List<NormalizedComponent> population = new ArrayList<>();
        for (NormalizedComponent component : doc.components()) {
            if (!CryptoAssets.isCryptoAsset(component.type())) {
                population.add(component);
            }
        }
        if (population.isEmpty()) {
            return null;
        }

        int n = population.size();
        long supplierCount = 0;
        long nameCount = 0;
        long versionCount = 0;
        long uniqueIdCount = 0;
        long dependencyCount = 0;

        for (NormalizedComponent component : population) {
            if (component.supplier() != null) {
                supplierCount++;
            }
            if (component.name() != null) {
                nameCount++;
            }
            if (component.version() != null) {
                versionCount++;
            }
            if (component.purl() != null || !component.identifiers().isEmpty() || !component.hashes().isEmpty()) {
                uniqueIdCount++;
            }
            if (component.bomRef() != null && doc.dependencyRelationshipRefs().contains(component.bomRef())) {
                dependencyCount++;
            }
        }

        boolean hasAuthor = !doc.authors().isEmpty();
        boolean hasTimestamp = doc.documentTimestamp() != null;

        int supplierCoverage = coveragePct(supplierCount, n);
        int nameCoverage = coveragePct(nameCount, n);
        int versionCoverage = coveragePct(versionCount, n);
        int uniqueIdCoverage = coveragePct(uniqueIdCount, n);
        int dependencyCoverage = coveragePct(dependencyCount, n);

        long numerator = 100L * (supplierCount + nameCount + versionCount + uniqueIdCount + dependencyCount
                + (hasAuthor ? n : 0L) + (hasTimestamp ? n : 0L));
        int score = (int) (numerator / (7L * n));

        SbomQualityScore result = new SbomQualityScore();
        result.setScore(score);
        result.setSupplierCoverage(supplierCoverage);
        result.setNameCoverage(nameCoverage);
        result.setVersionCoverage(versionCoverage);
        result.setUniqueIdCoverage(uniqueIdCoverage);
        result.setDependencyCoverage(dependencyCoverage);
        result.setHasAuthor(hasAuthor);
        result.setHasTimestamp(hasTimestamp);
        result.setComponentsScored(n);
        return result;
    }

    private static int coveragePct(long count, int n) {
        return (int) (100L * count / n);
    }

}
