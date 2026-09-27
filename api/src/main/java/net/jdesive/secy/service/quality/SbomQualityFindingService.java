package net.jdesive.secy.service.quality;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.SbomQualityFindingRepository;
import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.NtiaElement;
import net.jdesive.secy.persistence.entity.Product;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SbomLifecycleStage;
import net.jdesive.secy.persistence.entity.SbomQualityFinding;
import net.jdesive.secy.persistence.entity.SbomQualityScore;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * The Spring/JPA half of M1h's SBOM-quality finding engine: for one SBOM that just landed, decide
 * whether its slot (product, lifecycle stage — or the SBOM itself for a bucket product) should carry
 * a low-quality finding, and reconcile {@link SbomQualityFinding} against it. Triggered by
 * {@link SbomQualityFindingListener} after every relevant SBOM upload commits — see that class for
 * why after-commit rather than inline. Modeled on {@code QuantumFindingService}, but simpler: there
 * is no cross-SBOM union or diff here (unlike M1e/M1g) — the candidate is always exactly this one
 * SBOM's own score, and the only other SBOM this class ever reads is the product's active-slot set,
 * used solely to sweep findings for slots this SBOM's upload has superseded.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SbomQualityFindingService {

    private final SBOMRepository sbomRepository;
    private final SbomQualityFindingRepository findingRepository;

    /** What one {@link #reconcileForSbom} call did. Returned for logging/tests. */
    public record SbomQualityReconcileSummary(int created, int updated, int autoResolved) {
        public static final SbomQualityReconcileSummary EMPTY = new SbomQualityReconcileSummary(0, 0, 0);
    }

    /**
     * Reconcile {@code sbomId}'s slot against {@link SbomQualityFinding}, in a fresh transaction —
     * {@code REQUIRES_NEW} for the same reason as {@code QuantumFindingService.reconcileForSbom}: a
     * concurrent duplicate insert on the unique partial/expression index rolls back only the loser.
     *
     * <p>Skipped entirely (empty summary, DEBUG log) when the SBOM does not exist, is not
     * {@code active} (a newer upload to the same slot runs its own reconcile), or has no product.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public SbomQualityReconcileSummary reconcileForSbom(UUID sbomId) {
        SBOM sbom = sbomRepository.findById(sbomId).orElse(null);
        if (sbom == null) {
            log.debug("SBOM quality finding reconciliation skipped: SBOM {} not found", sbomId);
            return SbomQualityReconcileSummary.EMPTY;
        }
        if (!sbom.isActive()) {
            log.debug("SBOM quality finding reconciliation skipped: SBOM {} is no longer active (superseded)", sbomId);
            return SbomQualityReconcileSummary.EMPTY;
        }
        Product product = sbom.getProduct();
        if (product == null) {
            log.debug("SBOM quality finding reconciliation skipped: SBOM {} has no product", sbomId);
            return SbomQualityReconcileSummary.EMPTY;
        }

        boolean productScoped = !product.isUnassigned();
        UUID productId = product.getId();
        SbomLifecycleStage stage = sbom.getLifecycleStage();
        SbomQualityScore quality = sbom.getQuality();
        boolean low = quality != null && quality.getScore() != null
                && quality.getScore() < SbomQualityScorer.FINDING_THRESHOLD;

        List<SbomQualityFinding> prior = productScoped
                ? findingRepository.findAllByProductIdAndScopeSbomIdIsNull(productId)
                : findingRepository.findAllByScopeSbomId(sbomId);

        SbomQualityFinding slotFinding = null;
        for (SbomQualityFinding candidate : prior) {
            if (productScoped) {
                if (Objects.equals(candidate.getLifecycleStage(), stage)) {
                    slotFinding = candidate;
                    break;
                }
            } else {
                slotFinding = candidate;
                break;
            }
        }

        int created = 0;
        int updated = 0;
        int autoResolved = 0;
        List<SbomQualityFinding> toSave = new ArrayList<>();
        LocalDateTime now = LocalDateTime.now();

        if (low) {
            SbomQualityFinding finding = slotFinding;
            if (finding == null) {
                finding = new SbomQualityFinding();
                finding.setTenantId(sbom.getTenantId());
                finding.setProductId(productId);
                finding.setScopeSbomId(productScoped ? null : sbomId);
                finding.setLifecycleStage(stage);
                created++;
            } else {
                updated++;
            }
            finding.setSbomId(sbomId);
            finding.setQuality(quality.copy());
            finding.setScoreThreshold(SbomQualityScorer.FINDING_THRESHOLD);
            finding.setMissingElements(joinMissing(quality));
            finding.setSummary(truncate(summaryFor(quality, stage), 1024));
            finding.setLifecycleState(AlertLifecycleState.ACTIVE);
            finding.setLastSeenAt(now);
            toSave.add(finding);
        } else if (slotFinding != null && slotFinding.getLifecycleState() == AlertLifecycleState.ACTIVE) {
            slotFinding.setSbomId(sbomId);
            slotFinding.setLifecycleState(AlertLifecycleState.AUTO_RESOLVED);
            slotFinding.setLastSeenAt(now);
            toSave.add(slotFinding);
            autoResolved++;
        }

        if (productScoped) {
            Set<SbomLifecycleStage> activeStages = new HashSet<>();
            for (SBOM active : sbomRepository.findAllByProductIdAndActiveTrue(productId)) {
                activeStages.add(active.getLifecycleStage());
            }
            for (SbomQualityFinding candidate : prior) {
                if (candidate == slotFinding) {
                    continue;
                }
                if (candidate.getLifecycleState() != AlertLifecycleState.ACTIVE) {
                    continue;
                }
                if (activeStages.contains(candidate.getLifecycleStage())) {
                    continue;
                }
                candidate.setLifecycleState(AlertLifecycleState.AUTO_RESOLVED);
                candidate.setLastSeenAt(now);
                toSave.add(candidate);
                autoResolved++;
            }
        }

        if (!toSave.isEmpty()) {
            findingRepository.saveAll(toSave);
        }

        SbomQualityReconcileSummary summary = new SbomQualityReconcileSummary(created, updated, autoResolved);
        log.info("SBOM quality finding reconciliation for SBOM {} (product {}, scope {}): {}", sbomId, productId,
                productScoped ? "product" : "sbom", summary);
        return summary;
    }

    /* ------------------------------------------------------------------ */
    /* Summary text                                                        */
    /* ------------------------------------------------------------------ */

    private static String joinMissing(SbomQualityScore quality) {
        StringBuilder sb = new StringBuilder();
        for (NtiaElement element : quality.getMissingElements()) {
            if (sb.length() > 0) {
                sb.append(',');
            }
            sb.append(element.name());
        }
        return sb.toString();
    }

    private static String summaryFor(SbomQualityScore quality, SbomLifecycleStage stage) {
        StringBuilder sb = new StringBuilder();
        if (stage != null) {
            sb.append(stage.name()).append("-stage ");
        }
        sb.append("SBOM quality score ").append(quality.getScore()).append("/100 is below the threshold of ")
                .append(SbomQualityScorer.FINDING_THRESHOLD)
                .append(" against the NTIA minimum elements (")
                .append(quality.getComponentsScored()).append(" components scored). Incomplete: ");

        List<String> parts = new ArrayList<>();
        for (NtiaElement element : quality.getMissingElements()) {
            parts.add(switch (element) {
                case SUPPLIER -> "supplier (" + quality.getSupplierCoverage() + "% of components)";
                case COMPONENT_NAME -> "component name (" + quality.getNameCoverage() + "%)";
                case COMPONENT_VERSION -> "component version (" + quality.getVersionCoverage() + "%)";
                case UNIQUE_IDENTIFIER -> "unique identifier (" + quality.getUniqueIdCoverage() + "%)";
                case DEPENDENCY_RELATIONSHIP -> "dependency relationship (" + quality.getDependencyCoverage() + "%)";
                case AUTHOR -> "author (none declared)";
                case TIMESTAMP -> "timestamp (none declared)";
            });
        }
        sb.append(String.join(", ", parts));
        sb.append(". Regenerate this SBOM with a tool or configuration that emits these fields.");
        return sb.toString();
    }

    private static String truncate(String value, int max) {
        if (value == null) {
            return null;
        }
        return value.length() <= max ? value : value.substring(0, max);
    }

}
