package net.jdesive.secy.model.scoring;

import java.util.UUID;

/**
 * {@code GET /products/{id}/risk-score} / {@code GET /assets/{id}/risk-score} — the
 * <b>maximum</b> risk score among that scope's open, actionable, default-visible findings (the same
 * population {@code GET /actionable} shows by default for that scope), plus enough to explain why.
 *
 * <p>Deliberately the maximum, not a sum or an average: it is explainable by construction
 * ({@code topFindingId} names the row that produced it) and stays meaningful regardless of how many
 * findings a scope has — a product with one 92.8 and a product with fifty 92.8s roll up identically.
 *
 * @param scopeType             {@code PRODUCT} or {@code ASSET}
 * @param scopeId               the product or asset id
 * @param scopeName             its name, for display without a second lookup
 * @param score                 the maximum risk score among the scope's population, or null when
 *                              every finding in scope is unscored
 * @param topFindingId          the alert id that produced {@code score}, or null
 * @param findingCount          vulnerability alerts in the rollup population (scored or not)
 * @param unscoredFindingCount  of those, how many have no {@code riskScore} yet
 * @param compromiseFindingCount compromise findings in scope — counted separately, never folded into
 *                              {@code score}. See {@code ActionableService}'s Javadoc for why a
 *                              compromise finding has no commensurable score.
 * @param model                 the weights model version {@code score} was computed under
 */
public record RiskRollupResponse(
        String scopeType,
        UUID scopeId,
        String scopeName,
        Double score,
        UUID topFindingId,
        long findingCount,
        long unscoredFindingCount,
        long compromiseFindingCount,
        String model) {
}
