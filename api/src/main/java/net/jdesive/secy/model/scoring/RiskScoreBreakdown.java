package net.jdesive.secy.model.scoring;

import java.time.LocalDateTime;
import java.util.List;

/**
 * {@code GET /actionable/{id}}'s scoring block — the alert's <b>stored</b> snapshot alongside a
 * <b>freshly recomputed</b> one, the same pattern M1f's VEX block uses for statements vs. the stored
 * resolution.
 *
 * @param storedScore the alert's persisted {@code riskScore}, or null if never scored
 * @param storedModel the persisted {@code riskScoreModel}, or null
 * @param scoredAt    when the stored score was last written
 * @param score       freshly recomputed from the alert's current snapshots
 * @param model       the weights model version used for the fresh computation
 * @param current     true when the stored score/model agree with the freshly recomputed ones — false
 *                    means the row is due for a re-enrichment or a {@code POST /risk-score/rescore}
 * @param factors     the fresh computation's full breakdown
 */
public record RiskScoreBreakdown(
        Double storedScore,
        String storedModel,
        LocalDateTime scoredAt,
        double score,
        String model,
        boolean current,
        List<ScoreFactor> factors) {
}
