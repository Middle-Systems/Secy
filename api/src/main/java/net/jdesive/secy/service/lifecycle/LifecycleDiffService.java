package net.jdesive.secy.service.lifecycle;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.model.lifecycle.StageComponent;
import net.jdesive.secy.persistence.LifecycleDriftFindingRepository;
import net.jdesive.secy.persistence.SBOMComponentRepository;
import net.jdesive.secy.persistence.SBOMRepository;
import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.LifecycleDriftFinding;
import net.jdesive.secy.persistence.entity.LifecycleDriftKind;
import net.jdesive.secy.persistence.entity.LifecycleStagePair;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.service.lifecycle.LifecycleDiffer.Drift;
import net.jdesive.secy.service.lifecycle.LifecycleDiffer.LifecycleDiff;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.UUID;

/**
 * The Spring/JPA half of M1e's diff engine: for one SBOM that just landed, find its comparable
 * adjacent-stage counterpart(s) and reconcile {@link LifecycleDriftFinding} rows against the pure
 * {@link LifecycleDiffer}. Triggered by {@link LifecycleDiffListener} after every relevant SBOM
 * upload commits — see that class for why after-commit rather than inline.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class LifecycleDiffService {

    /** {@code SBOM.status} values a counterpart must be in to have components worth diffing against. */
    private static final Set<String> COMPARABLE_STATUSES = Set.of("PROCESSING", "COMPLETED");

    private final SBOMRepository sbomRepository;
    private final SBOMComponentRepository sbomComponentRepository;
    private final LifecycleDriftFindingRepository driftFindingRepository;

    /** What one {@link #runForSbom} call did, across every pair it evaluated. Returned for logging/tests. */
    public record LifecycleDiffRunSummary(int pairsEvaluated, int created, int updated, int autoResolved,
                                          int removedIgnored) {
        static final LifecycleDiffRunSummary EMPTY = new LifecycleDiffRunSummary(0, 0, 0, 0, 0);
    }

    /**
     * Diff {@code sbomId} against each of its stage's adjacent counterpart(s), in a fresh transaction.
     *
     * <p>{@code REQUIRES_NEW}: this runs from {@link LifecycleDiffListener}'s after-commit callback, on
     * the same job thread as the ingestion that just completed — a fresh transaction is what lets a
     * concurrent duplicate reconciliation (both sides of a pair committing and diffing around the same
     * time) collide on {@code uq_lifecycle_drift_finding_key} and have only the loser's transaction
     * roll back, rather than poisoning the ingestion's own transaction.
     *
     * <p>Skipped entirely (empty summary, logged at DEBUG) when the SBOM: does not exist; is not
     * {@code active} (a newer upload already superseded it — the newer one runs its own diff); has no
     * {@code lifecycleStage} (nothing to pair it with); has no product; or belongs to the Unassigned
     * bucket (bucket SBOMs are unrelated documents, not stages of one pipeline).
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public LifecycleDiffRunSummary runForSbom(UUID sbomId) {
        SBOM sbom = sbomRepository.findById(sbomId).orElse(null);
        if (sbom == null) {
            log.debug("Lifecycle diff skipped: SBOM {} not found", sbomId);
            return LifecycleDiffRunSummary.EMPTY;
        }
        if (!sbom.isActive()) {
            log.debug("Lifecycle diff skipped: SBOM {} is no longer active (superseded)", sbomId);
            return LifecycleDiffRunSummary.EMPTY;
        }
        if (sbom.getLifecycleStage() == null) {
            log.debug("Lifecycle diff skipped: SBOM {} has no lifecycle stage", sbomId);
            return LifecycleDiffRunSummary.EMPTY;
        }
        if (sbom.getProduct() == null || sbom.getProduct().isUnassigned()) {
            log.debug("Lifecycle diff skipped: SBOM {} has no product, or is in the Unassigned bucket", sbomId);
            return LifecycleDiffRunSummary.EMPTY;
        }

        UUID productId = sbom.getProduct().getId();
        List<LifecycleStagePair> pairs = LifecycleStagePair.involving(sbom.getLifecycleStage());

        int created = 0;
        int updated = 0;
        int autoResolved = 0;
        int removedIgnored = 0;
        int pairsEvaluated = 0;

        for (LifecycleStagePair pair : pairs) {
            var counterpartOpt = sbomRepository.findFirstByProductIdAndLifecycleStageAndActiveTrueOrderByUploadDateDesc(
                    productId, pair.counterpartOf(sbom.getLifecycleStage()));
            if (counterpartOpt.isEmpty() || !COMPARABLE_STATUSES.contains(counterpartOpt.get().getStatus())) {
                log.debug("Lifecycle diff: no comparable counterpart for {} on product {}", pair, productId);
                continue;
            }
            SBOM counterpart = counterpartOpt.get();

            SBOM baselineSbom = sbom.getLifecycleStage() == pair.baseline() ? sbom : counterpart;
            SBOM observedSbom = sbom.getLifecycleStage() == pair.baseline() ? counterpart : sbom;

            List<StageComponent> baselineComponents = sbomComponentRepository.findStageComponents(baselineSbom.getId());
            List<StageComponent> observedComponents = sbomComponentRepository.findStageComponents(observedSbom.getId());

            LifecycleDiff diff = LifecycleDiffer.diff(baselineComponents, observedComponents);
            removedIgnored += diff.removedIdentityKeys().size();
            pairsEvaluated++;

            ReconcileResult result = reconcile(productId, pair, baselineSbom, observedSbom, diff);
            created += result.created();
            updated += result.updated();
            autoResolved += result.autoResolved();
        }

        LifecycleDiffRunSummary summary =
                new LifecycleDiffRunSummary(pairsEvaluated, created, updated, autoResolved, removedIgnored);
        log.info("Lifecycle diff for SBOM {} (product {}, stage {}): {}", sbomId, productId,
                sbom.getLifecycleStage(), summary);
        return summary;
    }

    /* ------------------------------------------------------------------ */
    /* Reconciliation                                                      */
    /* ------------------------------------------------------------------ */

    private record ReconcileResult(int created, int updated, int autoResolved) {
    }

    /**
     * Upsert-and-auto-resolve for one stage pair, keyed on {@code (driftKind, identityKey)} — mirrors
     * {@code CompromiseDetectionService.reconcile}'s pattern.
     */
    private ReconcileResult reconcile(UUID productId, LifecycleStagePair pair, SBOM baselineSbom, SBOM observedSbom,
                                      LifecycleDiff diff) {
        List<LifecycleDriftFinding> prior = driftFindingRepository.findAllByProductIdAndStagePair(productId, pair);
        Map<Key, LifecycleDriftFinding> existing = new LinkedHashMap<>();
        for (LifecycleDriftFinding finding : prior) {
            existing.putIfAbsent(new Key(finding.getDriftKind(), finding.getIdentityKey()), finding);
        }

        Map<Key, Drift> candidates = new LinkedHashMap<>();
        for (Drift drift : diff.unexpected()) {
            candidates.put(new Key(LifecycleDriftKind.UNEXPECTED_COMPONENT, drift.identityKey()), drift);
        }
        for (Drift drift : diff.versionMismatches()) {
            candidates.put(new Key(LifecycleDriftKind.VERSION_MISMATCH, drift.identityKey()), drift);
        }

        LocalDateTime now = LocalDateTime.now();
        List<LifecycleDriftFinding> toSave = new ArrayList<>();
        int created = 0;
        int updated = 0;

        for (Map.Entry<Key, Drift> entry : candidates.entrySet()) {
            Key key = entry.getKey();
            Drift drift = entry.getValue();

            LifecycleDriftFinding finding = existing.get(key);
            if (finding == null) {
                finding = new LifecycleDriftFinding();
                finding.setTenantId(baselineSbom.getTenantId());
                finding.setProductId(productId);
                finding.setStagePair(pair);
                finding.setDriftKind(key.kind());
                finding.setIdentityKey(key.identityKey());
                created++;
            } else {
                updated++;
            }

            finding.setBaselineSbomId(baselineSbom.getId());
            finding.setObservedSbomId(observedSbom.getId());
            finding.setObservedComponentId(
                    drift.representative() == null ? null : drift.representative().componentId());
            finding.setComponentName(truncate(drift.representative() == null ? null : drift.representative().name(), 255));
            finding.setComponentPurl(truncate(drift.representative() == null ? null : drift.representative().purl(), 512));
            finding.setObservedVersion(truncate(joined(drift.observedVersions()), 255));
            finding.setBaselineVersion(key.kind() == LifecycleDriftKind.UNEXPECTED_COMPONENT
                    ? null : truncate(joined(drift.baselineVersions()), 255));
            finding.setSummary(truncate(summaryFor(pair, key.kind(), drift), 1024));
            finding.setLifecycleState(AlertLifecycleState.ACTIVE);
            finding.setLastSeenAt(now);

            toSave.add(finding);
        }

        int autoResolved = 0;
        for (Map.Entry<Key, LifecycleDriftFinding> entry : existing.entrySet()) {
            if (candidates.containsKey(entry.getKey())) {
                continue;
            }
            LifecycleDriftFinding stale = entry.getValue();
            if (stale.getLifecycleState() == AlertLifecycleState.AUTO_RESOLVED) {
                continue;
            }
            stale.setLifecycleState(AlertLifecycleState.AUTO_RESOLVED);
            toSave.add(stale);
            autoResolved++;
        }

        if (!toSave.isEmpty()) {
            driftFindingRepository.saveAll(toSave);
        }

        return new ReconcileResult(created, updated, autoResolved);
    }

    private record Key(LifecycleDriftKind kind, String identityKey) {
    }

    /* ------------------------------------------------------------------ */
    /* Summary text                                                        */
    /* ------------------------------------------------------------------ */

    /**
     * The exact summary wording per pair/kind — see {@code LifecycleDiffService}'s class Javadoc table
     * (ROADMAP.md, M1e). {@code <c>} is the representative component's name, {@code <key>} its
     * identity key, {@code <obs>}/{@code <base>} the joined observed/baseline versions.
     */
    private static String summaryFor(LifecycleStagePair pair, LifecycleDriftKind kind, Drift drift) {
        String componentName = drift.representative() != null && drift.representative().name() != null
                ? drift.representative().name() : drift.identityKey();
        String observed = joined(drift.observedVersions());
        String baseline = joined(drift.baselineVersions());

        return switch (pair) {
            case SOURCE_BUILD -> kind == LifecycleDriftKind.UNEXPECTED_COMPONENT
                    ? componentName + " is in the Build SBOM but was not declared in the Source SBOM — possible "
                      + "dependency confusion or build-time injection."
                    : "Build resolved " + drift.identityKey() + " to " + observed + " but the Source SBOM declares "
                      + baseline + " — possible dependency confusion (substituted version).";
            case BUILD_DEPLOYED -> kind == LifecycleDriftKind.UNEXPECTED_COMPONENT
                    ? componentName + " is running in the Deployed SBOM but was not produced by the Build — "
                      + "runtime drift or unauthorized change."
                    : "Deployed runs " + drift.identityKey() + " " + observed + " but the Build produced "
                      + baseline + " — runtime drift or unauthorized change.";
            case BUILD_ANALYZED -> kind == LifecycleDriftKind.UNEXPECTED_COMPONENT
                    ? componentName + " was found by post-build analysis but is absent from the Build SBOM — "
                      + "incomplete build SBOM or post-build tampering."
                    : "Post-build analysis found " + drift.identityKey() + " " + observed + " but the Build SBOM "
                      + "declares " + baseline + " — inaccurate build SBOM or tampering.";
        };
    }

    private static String joined(SortedSet<String> versions) {
        return versions == null || versions.isEmpty() ? "" : String.join(", ", versions);
    }

    private static String truncate(String value, int max) {
        if (value == null) {
            return null;
        }
        return value.length() <= max ? value : value.substring(0, max);
    }

}
