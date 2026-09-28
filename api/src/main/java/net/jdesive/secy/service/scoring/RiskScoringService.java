package net.jdesive.secy.service.scoring;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.model.ingest.IngestResult;
import net.jdesive.secy.model.ingest.JobProgress;
import net.jdesive.secy.model.scoring.RiskScoreResult;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.entity.Tenant;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Slice;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Writes and explains the M1i risk score (ROADMAP.md — "Scoring engine rework"). The only writer of
 * {@link VulnerabilityAlert#getRiskScore()}/{@link VulnerabilityAlert#getRiskScoreModel()}/
 * {@link VulnerabilityAlert#getRiskScoredAt()} — never touched directly by
 * {@code EnrichmentService} or {@code VexResolutionService}, which each call {@link #apply} as their
 * last step instead. See {@link RiskScorer} for the pure formula this wraps.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RiskScoringService {

    /** Alerts rescored per flush — same batch size as {@code EnrichmentService.reEnrichAll}. */
    private static final int BATCH_SIZE = 500;

    private final ScoringWeightsProvider weightsProvider;

    private final VulnerabilityAlertRepository alertRepository;

    @PersistenceContext
    private EntityManager entityManager;

    /**
     * Recompute and store {@code alert}'s risk score from its current snapshots. Clears the score
     * when the alert has no CVE (mirrors {@code EnrichmentService.enrich}'s own cve-null branch:
     * total, not additive). Never saves — callers already own the save.
     */
    public void apply(VulnerabilityAlert alert) {
        Double beforeScore = alert.getRiskScore();
        String beforeModel = alert.getRiskScoreModel();

        if (alert.getVulnerability() == null) {
            alert.setRiskScore(null);
            alert.setRiskScoreModel(null);
        } else {
            RiskScoreResult result = computeResult(alert);
            alert.setRiskScore(result.score());
            alert.setRiskScoreModel(result.model());
        }

        boolean changed = !Objects.equals(beforeScore, alert.getRiskScore())
                || !Objects.equals(beforeModel, alert.getRiskScoreModel());
        if (changed) {
            alert.setRiskScoredAt(LocalDateTime.now());
        }
    }

    /** The full breakdown behind {@code alert}'s current snapshots, freshly recomputed — never stored. */
    public RiskScoreResult explain(VulnerabilityAlert alert) {
        return computeResult(alert);
    }

    private RiskScoreResult computeResult(VulnerabilityAlert alert) {
        UUID tenantId = alert.getTenantId() == null ? Tenant.DEFAULT_TENANT_ID : alert.getTenantId();
        ScoringWeights weights = weightsProvider.forTenant(tenantId);
        return RiskScorer.score(RiskScoreInputs.from(alert), weights);
    }

    /**
     * Rescore every alert from its current snapshots — the {@code RISK_RESCORE} job's body. No
     * enrichment side effects: this only ever touches the three risk-score columns. Pages by id in
     * batches of {@value #BATCH_SIZE}, flushing and clearing the persistence context each batch, the
     * same shape as {@code EnrichmentService.reEnrichAll}.
     */
    @Transactional
    public IngestResult rescoreAll(JobProgress progress) {
        long total = alertRepository.count();
        if (total == 0) {
            return new IngestResult(0, "0 alerts rescored");
        }

        log.info("Rescoring {} vulnerability alerts against the current weights model", total);
        int processed = 0;
        int changed = 0;
        int pageNumber = 0;

        while (true) {
            Slice<UUID> idSlice = alertRepository.findIdsForRescore(PageRequest.of(pageNumber, BATCH_SIZE, Sort.by("id")));
            List<UUID> ids = idSlice.getContent();
            if (ids.isEmpty()) {
                break;
            }

            List<VulnerabilityAlert> alerts = alertRepository.findAllForRescore(ids);
            for (VulnerabilityAlert alert : alerts) {
                Double beforeScore = alert.getRiskScore();
                String beforeModel = alert.getRiskScoreModel();
                apply(alert);
                if (!Objects.equals(beforeScore, alert.getRiskScore()) || !Objects.equals(beforeModel, alert.getRiskScoreModel())) {
                    changed++;
                }
            }
            alertRepository.saveAll(alerts);
            entityManager.flush();
            entityManager.clear();

            processed += ids.size();
            progress.report(processed, processed + "/" + total + " alerts rescored");
            if (!idSlice.hasNext()) {
                break;
            }
            pageNumber++;
        }

        String message = processed + " alerts rescored (" + changed + " changed)";
        log.info(message);
        return new IngestResult(processed, message);
    }

}
