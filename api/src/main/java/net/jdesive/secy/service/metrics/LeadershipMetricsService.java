package net.jdesive.secy.service.metrics;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.Tuple;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Expression;
import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.JoinType;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import lombok.RequiredArgsConstructor;
import net.jdesive.secy.model.actionable.ActionableFilter;
import net.jdesive.secy.model.actionitem.ActionItemResponse;
import net.jdesive.secy.model.metrics.LeadershipMetricsResponse;
import net.jdesive.secy.model.metrics.LeadershipMetricsResponse.CurrentRisk;
import net.jdesive.secy.model.metrics.LeadershipMetricsResponse.KevExposure;
import net.jdesive.secy.model.metrics.LeadershipMetricsResponse.Mttr;
import net.jdesive.secy.model.metrics.LeadershipMetricsResponse.ProductCoverage;
import net.jdesive.secy.model.metrics.LeadershipMetricsResponse.RiskTrend;
import net.jdesive.secy.model.metrics.LeadershipMetricsResponse.SbomStageCoverage;
import net.jdesive.secy.model.metrics.LeadershipMetricsResponse.SeverityCounts;
import net.jdesive.secy.model.metrics.LeadershipMetricsResponse.Summary;
import net.jdesive.secy.model.metrics.LeadershipMetricsResponse.WeeklyFlowEntry;
import net.jdesive.secy.persistence.CompromiseFindingRepository;
import net.jdesive.secy.persistence.LifecycleDriftFindingRepository;
import net.jdesive.secy.persistence.ProductRepository;
import net.jdesive.secy.persistence.QuantumVulnerabilityFindingRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.SbomQualityFindingRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.entity.ActionableReason;
import net.jdesive.secy.persistence.entity.FindingType;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.RemediationStatus;
import net.jdesive.secy.persistence.entity.SbomLifecycleStage;
import net.jdesive.secy.persistence.entity.Tenant;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;
import net.jdesive.secy.service.ActionableService;
import net.jdesive.secy.service.actionitem.ActionItemService;
import net.jdesive.secy.service.finding.FindingService;
import net.jdesive.secy.service.scoring.RiskRollupService;
import net.jdesive.secy.service.scoring.ScoringWeights;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.DayOfWeek;
import java.time.Duration;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * {@code GET /metrics/leadership} (M1k — ROADMAP.md's "Role-based views" §5). Every population here
 * is built to agree with an existing, already-pinned endpoint by construction — see each field's
 * Javadoc on {@link LeadershipMetricsResponse} — rather than inventing a parallel definition of
 * "severity" or "open" that could silently drift from {@code /actionable}/{@code /findings}.
 *
 * <h2>Honesty over completeness</h2>
 *
 * <p>{@link #riskTrend} is always {@code available=false}: {@code vulnerability_alert.risk_score}
 * is overwritten in place on every rescore, so there is no history to plot without a snapshot table
 * and a scheduled job — and Secy has no scheduler beyond the job queue. {@link #mttr} measures time
 * from an action item's creation to its MOST RECENT resolution: a reopen-and-re-resolve cycle
 * overwrites {@code resolvedAt}, so earlier cycles are not counted even though the event history
 * has them; items reopened by derivation are excluded entirely (their stored status is RESOLVED but
 * the effective one is not); {@code resolvedAt} is a human claim, and {@code fixVerifiedCount} is
 * how many of those are additionally scan-verified (no linked finding remains active). Findings
 * never grouped into an action item have no resolution timestamp at all — finding-level MTTR is
 * deferred; adding one would touch all five reconcile services M1j deliberately left untouched.
 */
@Service
@RequiredArgsConstructor
public class LeadershipMetricsService {

    private static final List<SbomLifecycleStage> ALL_STAGES = List.of(
            SbomLifecycleStage.SOURCE, SbomLifecycleStage.BUILD, SbomLifecycleStage.ANALYZED, SbomLifecycleStage.DEPLOYED);

    private static final ActionableFilter ALL_NULL_FILTER =
            new ActionableFilter(null, null, null, null, null, null, null, null, null, null, null, null, null);

    private final ActionableService actionableService;
    private final FindingService findingService;
    private final ActionItemService actionItemService;
    private final ProductRepository productRepository;
    private final SBOMRepository sbomRepository;
    private final RiskRollupService riskRollupService;
    private final VulnerabilityAlertRepository alertRepository;
    private final CompromiseFindingRepository compromiseFindingRepository;
    private final LifecycleDriftFindingRepository lifecycleDriftFindingRepository;
    private final QuantumVulnerabilityFindingRepository quantumVulnerabilityFindingRepository;
    private final SbomQualityFindingRepository sbomQualityFindingRepository;

    @PersistenceContext
    private EntityManager entityManager;

    @Transactional(readOnly = true)
    public LeadershipMetricsResponse build(int mttrWindowDays) {
        return new LeadershipMetricsResponse(
                LocalDateTime.now(),
                ScoringWeights.DEFAULT.modelVersion(),
                findingsBySeverity(),
                findingService.countsByType(),
                kevExposure(),
                currentRisk(),
                riskTrend(),
                weeklyFlow(),
                mttr(mttrWindowDays),
                sbomStageCoverage());
    }

    /* ------------------------------------------------------------------ */
    /* Severity                                                            */
    /* ------------------------------------------------------------------ */

    private SeverityCounts findingsBySeverity() {
        CriteriaBuilder cb = entityManager.getCriteriaBuilder();
        CriteriaQuery<Tuple> query = cb.createTupleQuery();
        Root<VulnerabilityAlert> root = query.from(VulnerabilityAlert.class);
        Join<VulnerabilityAlert, ?> vulnerability = root.join("vulnerability", JoinType.LEFT);
        Expression<String> severity = cb.upper(vulnerability.get("baseSeverity"));
        query.multiselect(severity, cb.count(root));
        query.where(ActionableService.vulnerabilityPredicate(root, cb, ALL_NULL_FILTER));
        query.groupBy(severity);

        long critical = 0, high = 0, medium = 0, low = 0, unknown = 0, total = 0;
        for (Tuple row : entityManager.createQuery(query).getResultList()) {
            String band = row.get(0, String.class);
            long count = row.get(1, Long.class);
            total += count;
            switch (band == null ? "" : band) {
                case "CRITICAL" -> critical += count;
                case "HIGH" -> high += count;
                case "MEDIUM" -> medium += count;
                case "LOW" -> low += count;
                default -> unknown += count;
            }
        }
        return new SeverityCounts(critical, high, medium, low, unknown, total);
    }

    /* ------------------------------------------------------------------ */
    /* KEV exposure                                                        */
    /* ------------------------------------------------------------------ */

    private KevExposure kevExposure() {
        Set<ActionableReason> kevReasons = Set.of(ActionableReason.KEV, ActionableReason.KEV_AND_EPSS_HIGH);
        CriteriaBuilder cb = entityManager.getCriteriaBuilder();

        long kevFindingCount = countKev(cb, kevReasons, null);
        long kevPastDueCount = countKev(cb, kevReasons, LocalDate.now());

        CriteriaQuery<Tuple> stageQuery = cb.createTupleQuery();
        Root<VulnerabilityAlert> stageRoot = stageQuery.from(VulnerabilityAlert.class);
        Join<VulnerabilityAlert, ?> component = stageRoot.join("component", JoinType.LEFT);
        Join<?, ?> sbom = component.join("sbom", JoinType.LEFT);
        Expression<String> stageLabel = cb.<String>selectCase()
                .when(cb.isNull(component.get("id")), "ASSET")
                .when(cb.isNull(sbom.get("lifecycleStage")), "UNSTAGED")
                .otherwise(sbom.get("lifecycleStage").as(String.class));
        stageQuery.multiselect(stageLabel, cb.count(stageRoot));
        List<Predicate> stagePredicates = new ArrayList<>();
        stagePredicates.add(ActionableService.vulnerabilityPredicate(stageRoot, cb, ALL_NULL_FILTER));
        stagePredicates.add(stageRoot.get("actionableReason").in(kevReasons));
        stageQuery.where(cb.and(stagePredicates.toArray(new Predicate[0])));
        stageQuery.groupBy(stageLabel);

        Map<String, Long> byStage = new LinkedHashMap<>();
        for (SbomLifecycleStage s : ALL_STAGES) {
            byStage.put(s.name(), 0L);
        }
        byStage.put("UNSTAGED", 0L);
        byStage.put("ASSET", 0L);
        for (Tuple row : entityManager.createQuery(stageQuery).getResultList()) {
            String label = row.get(0, String.class);
            byStage.put(label == null ? "UNSTAGED" : label, row.get(1, Long.class));
        }

        CriteriaQuery<Long> productsQuery = cb.createQuery(Long.class);
        Root<VulnerabilityAlert> pRoot = productsQuery.from(VulnerabilityAlert.class);
        Join<VulnerabilityAlert, ?> pComponent = pRoot.join("component", JoinType.LEFT);
        Join<?, ?> pSbom = pComponent.join("sbom", JoinType.LEFT);
        productsQuery.select(cb.countDistinct(pSbom.get("product").get("id")));
        List<Predicate> pPredicates = new ArrayList<>();
        pPredicates.add(ActionableService.vulnerabilityPredicate(pRoot, cb, ALL_NULL_FILTER));
        pPredicates.add(pRoot.get("actionableReason").in(kevReasons));
        productsQuery.where(cb.and(pPredicates.toArray(new Predicate[0])));
        long productsWithKevCount = entityManager.createQuery(productsQuery).getSingleResult();

        return new KevExposure(kevFindingCount, kevPastDueCount, byStage, productsWithKevCount);
    }

    private long countKev(CriteriaBuilder cb, Set<ActionableReason> kevReasons, LocalDate pastDueBefore) {
        CriteriaQuery<Long> query = cb.createQuery(Long.class);
        Root<VulnerabilityAlert> root = query.from(VulnerabilityAlert.class);
        query.select(cb.count(root));
        List<Predicate> predicates = new ArrayList<>();
        predicates.add(ActionableService.vulnerabilityPredicate(root, cb, ALL_NULL_FILTER));
        predicates.add(root.get("actionableReason").in(kevReasons));
        if (pastDueBefore != null) {
            predicates.add(cb.isNotNull(root.get("kevDueDate")));
            predicates.add(cb.lessThan(root.<LocalDate>get("kevDueDate"), pastDueBefore));
        }
        query.where(cb.and(predicates.toArray(new Predicate[0])));
        return entityManager.createQuery(query).getSingleResult();
    }

    /* ------------------------------------------------------------------ */
    /* Current risk                                                        */
    /* ------------------------------------------------------------------ */

    private CurrentRisk currentRisk() {
        ActionableService.RollupCounts counts = actionableService.vulnerabilityRollup(ALL_NULL_FILTER);
        long scored = counts.findingCount() - counts.unscoredFindingCount();
        return new CurrentRisk(counts.maxScore(), counts.topFindingId(), scored, counts.unscoredFindingCount());
    }

    private RiskTrend riskTrend() {
        return new RiskTrend(false, "No risk-score history is stored (vulnerability_alert.risk_score is "
                + "overwritten in place); a trend needs a snapshot table plus a scheduled job, and Secy "
                + "has no scheduler beyond the job queue. Deferred.");
    }

    /* ------------------------------------------------------------------ */
    /* Weekly flow                                                         */
    /* ------------------------------------------------------------------ */

    private List<WeeklyFlowEntry> weeklyFlow() {
        LocalDate currentMonday = LocalDate.now().with(DayOfWeek.MONDAY);
        LocalDate earliestMonday = currentMonday.minusWeeks(11);
        LocalDateTime since = earliestMonday.atStartOfDay();

        List<LocalDateTime> newFindingTimestamps = new ArrayList<>();
        newFindingTimestamps.addAll(alertRepository.findCreatedAtSinceActionable(since));
        newFindingTimestamps.addAll(compromiseFindingRepository.findCreatedAtSince(since));
        newFindingTimestamps.addAll(lifecycleDriftFindingRepository.findCreatedAtSince(since));
        newFindingTimestamps.addAll(quantumVulnerabilityFindingRepository.findCreatedAtSince(since));
        newFindingTimestamps.addAll(sbomQualityFindingRepository.findCreatedAtSince(since));

        List<ActionItemResponse> items = actionItemService.listAllEffective();

        List<WeeklyFlowEntry> entries = new ArrayList<>(12);
        for (int i = 11; i >= 0; i--) {
            LocalDate weekStart = currentMonday.minusWeeks(i);
            LocalDate weekEnd = weekStart.plusWeeks(1);
            long newFindings = countInWeek(newFindingTimestamps, weekStart, weekEnd);
            long created = items.stream()
                    .filter(it -> inWeek(it.createdAt(), weekStart, weekEnd)).count();
            long resolved = items.stream()
                    .filter(it -> it.status() == RemediationStatus.RESOLVED)
                    .filter(it -> inWeek(it.resolvedAt(), weekStart, weekEnd)).count();
            entries.add(new WeeklyFlowEntry(weekStart, newFindings, created, resolved));
        }
        return entries;
    }

    private static long countInWeek(List<LocalDateTime> timestamps, LocalDate weekStart, LocalDate weekEnd) {
        return timestamps.stream().filter(t -> inWeek(t, weekStart, weekEnd)).count();
    }

    private static boolean inWeek(LocalDateTime t, LocalDate weekStart, LocalDate weekEnd) {
        if (t == null) {
            return false;
        }
        LocalDate d = t.toLocalDate();
        return !d.isBefore(weekStart) && d.isBefore(weekEnd);
    }

    /* ------------------------------------------------------------------ */
    /* MTTR                                                                */
    /* ------------------------------------------------------------------ */

    private Mttr mttr(int windowDays) {
        LocalDateTime windowStart = LocalDateTime.now().minusDays(windowDays);
        List<ActionItemResponse> items = actionItemService.listAllEffective();

        List<ActionItemResponse> resolved = items.stream()
                .filter(it -> it.status() == RemediationStatus.RESOLVED)
                .filter(it -> it.resolvedAt() != null && it.resolvedAt().isAfter(windowStart))
                .toList();

        List<Double> hours = resolved.stream()
                .filter(it -> it.createdAt() != null)
                .map(it -> Duration.between(it.createdAt(), it.resolvedAt()).toMinutes() / 60.0)
                .sorted()
                .toList();

        Double mean = hours.isEmpty() ? null : hours.stream().mapToDouble(Double::doubleValue).average().orElse(0);
        Double median = median(hours);

        long fixVerified = resolved.stream().filter(ActionItemResponse::fixVerified).count();
        long awaitingVerification = resolved.stream().filter(ActionItemResponse::awaitingVerification).count();

        String note = "Measures time from creation to the MOST RECENT resolution -- a reopen-and-re-resolve "
                + "cycle overwrites resolvedAt, so earlier cycles aren't counted even though the event "
                + "history has them. Items reopened by derivation (effective status != stored RESOLVED) "
                + "are excluded. resolvedAt is a human claim; fixVerifiedCount says how many are "
                + "additionally scan-verified (no linked finding remains active). Findings never grouped "
                + "into an action item have no resolution timestamp -- finding-level MTTR is deferred.";

        return new Mttr("ACTION_ITEMS", windowDays, resolved.size(), mean, median, fixVerified, awaitingVerification, note);
    }

    private static Double median(List<Double> sortedValues) {
        if (sortedValues.isEmpty()) {
            return null;
        }
        int n = sortedValues.size();
        if (n % 2 == 1) {
            return sortedValues.get(n / 2);
        }
        return (sortedValues.get(n / 2 - 1) + sortedValues.get(n / 2)) / 2.0;
    }

    /* ------------------------------------------------------------------ */
    /* SBOM stage coverage                                                 */
    /* ------------------------------------------------------------------ */

    private SbomStageCoverage sbomStageCoverage() {
        List<Product> products = productRepository.findAll().stream()
                .filter(p -> Tenant.DEFAULT_TENANT_ID.equals(p.getTenantId()) && !p.isUnassigned())
                .toList();

        Map<UUID, Set<SbomLifecycleStage>> stagesByProduct = new LinkedHashMap<>();
        Map<UUID, Boolean> hasUnstagedByProduct = new LinkedHashMap<>();
        for (Object[] row : sbomRepository.findActiveStageRowsForNonBucketProducts()) {
            UUID productId = (UUID) row[0];
            SbomLifecycleStage stage = (SbomLifecycleStage) row[1];
            if (stage == null) {
                hasUnstagedByProduct.put(productId, true);
            } else {
                stagesByProduct.computeIfAbsent(productId, k -> new java.util.LinkedHashSet<>()).add(stage);
            }
        }

        List<ProductCoverage> coverageList = new ArrayList<>(products.size());
        int productsWithNoSbom = 0, productsLegacyOnly = 0, productsStaged = 0, productsWithAllFourStages = 0;
        Map<String, Integer> productsWithStage = new LinkedHashMap<>();
        for (SbomLifecycleStage s : ALL_STAGES) {
            productsWithStage.put(s.name(), 0);
        }

        for (Product product : products) {
            Set<SbomLifecycleStage> present = stagesByProduct.getOrDefault(product.getId(), Set.of());
            boolean hasUnstaged = hasUnstagedByProduct.getOrDefault(product.getId(), false);

            String mode;
            if (!present.isEmpty()) {
                mode = "STAGED";
                productsStaged++;
            } else if (hasUnstaged) {
                mode = "LEGACY";
                productsLegacyOnly++;
            } else {
                mode = "NONE";
                productsWithNoSbom++;
            }

            List<String> stagesPresent = ALL_STAGES.stream().filter(present::contains).map(Enum::name).toList();
            List<String> stagesMissing = ALL_STAGES.stream().filter(s -> !present.contains(s)).map(Enum::name).toList();
            for (SbomLifecycleStage s : present) {
                productsWithStage.merge(s.name(), 1, Integer::sum);
            }
            if (present.size() == ALL_STAGES.size()) {
                productsWithAllFourStages++;
            }

            Double maxRiskScore = riskRollupService.forProduct(product.getId())
                    .map(net.jdesive.secy.model.scoring.RiskRollupResponse::score)
                    .orElse(null);

            coverageList.add(new ProductCoverage(product.getId(), product.getName(), mode,
                    stagesPresent, stagesMissing, hasUnstaged, maxRiskScore));
        }

        Summary summary = new Summary(products.size(), productsWithNoSbom, productsLegacyOnly, productsStaged,
                productsWithAllFourStages, productsWithStage);
        return new SbomStageCoverage(summary, coverageList);
    }

}
