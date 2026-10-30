package net.jdesive.secy.model.metrics;

import net.jdesive.secy.persistence.entity.FindingType;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * {@code GET /metrics/leadership} (M1k — ROADMAP.md's "Role-based views" §5). AGGREGATES ONLY, no
 * finding rows — only ids for drill-down links, per the roadmap's "no row-level drill-down by
 * default". See {@code LeadershipMetricsService} for exactly how each field's population is
 * computed and why it agrees with its sibling endpoint by construction.
 */
public record LeadershipMetricsResponse(
        LocalDateTime generatedAt,
        String scoringModelVersion,
        SeverityCounts findingsBySeverity,
        Map<FindingType, Long> openFindingsByType,
        KevExposure kevExposure,
        CurrentRisk currentRisk,
        RiskTrend riskTrend,
        List<WeeklyFlowEntry> weeklyFlow,
        Mttr mttr,
        SbomStageCoverage sbomStageCoverage) {

    /**
     * Population: the default {@code GET /actionable} vulnerability population
     * ({@code ActionableService.vulnerabilityPredicate} with an all-null filter) grouped by the
     * CVE's {@code baseSeverity}, upper-cased. {@code total} agrees with
     * {@code GET /actionable?itemType=VULNERABILITY}'s {@code totalElements} by construction.
     */
    public record SeverityCounts(long critical, long high, long medium, long low, long unknown, long total) {
    }

    /**
     * Population: the default actionable predicate AND {@code actionableReason IN (KEV,
     * KEV_AND_EPSS_HIGH)}.
     *
     * @param kevByLifecycleStage keyed by {@code SOURCE}/{@code BUILD}/{@code ANALYZED}/
     *                            {@code DEPLOYED}/{@code UNSTAGED} (SBOM-derived, stage null) /
     *                            {@code ASSET} (no component at all)
     * @param productsWithKevCount distinct SBOM-derived products in the KEV population
     */
    public record KevExposure(long kevFindingCount, long kevPastDueCount,
                               Map<String, Long> kevByLifecycleStage, long productsWithKevCount) {
    }

    /** From {@code ActionableService.vulnerabilityRollup} with an all-null filter — same "max, explainable" semantics as a product/asset rollup. */
    public record CurrentRisk(Double maxRiskScore, UUID topFindingId, long scoredFindingCount, long unscoredFindingCount) {
    }

    /**
     * {@code available} is always {@code false} today — {@code vulnerability_alert.risk_score} is
     * overwritten in place, so there is no history to trend. Follows M1i's
     * {@code DEPENDENCY_DEPTH available=false} precedent; never faked.
     */
    public record RiskTrend(boolean available, String note) {
    }

    /**
     * One ISO week (Monday-aligned) of raw throughput — labelled as throughput, not risk.
     *
     * @param newFindings findings (all 5 tables) created in this week, regardless of current state;
     *                    vulnerabilities restricted to {@code actionable = true} (CURRENT value, not
     *                    a historical snapshot — a since-fixed CVE's creation week still counts if
     *                    it happens to be actionable today, and vice versa)
     */
    public record WeeklyFlowEntry(LocalDate weekStart, long newFindings, long actionItemsCreated, long actionItemsResolved) {
    }

    /**
     * Population: action items with effective status {@code RESOLVED} and {@code resolvedAt} within
     * the window. See {@code LeadershipMetricsService}'s Javadoc for the full honesty caveats this
     * carries (reopen-and-re-resolve, derivation-excluded items, finding-level MTTR not existing).
     */
    public record Mttr(String basis, int windowDays, long resolvedCount, Double meanHours, Double medianHours,
                        long fixVerifiedCount, long awaitingVerificationCount, String note) {
    }

    public record SbomStageCoverage(Summary summary, List<ProductCoverage> products) {
    }

    public record Summary(int productCount, int productsWithNoSbom, int productsLegacyOnly, int productsStaged,
                           int productsWithAllFourStages, Map<String, Integer> productsWithStage) {
    }

    /** {@code maxRiskScore} from {@code RiskRollupService.forProduct(id)} — one call per product (N+1, acceptable at this volume). */
    public record ProductCoverage(UUID productId, String productName, String mode, List<String> stagesPresent,
                                   List<String> stagesMissing, boolean hasUnstagedActiveSbom, Double maxRiskScore) {
    }

}
