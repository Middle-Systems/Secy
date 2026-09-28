package net.jdesive.secy.model.scoring;

import java.util.List;

/**
 * The output of {@code RiskScorer.score} — the final 0-100 score, the weights model that produced
 * it, and the full per-factor breakdown, in {@link net.jdesive.secy.service.scoring.ScoreInput}
 * declaration order.
 */
public record RiskScoreResult(double score, String model, List<ScoreFactor> factors) {
}
