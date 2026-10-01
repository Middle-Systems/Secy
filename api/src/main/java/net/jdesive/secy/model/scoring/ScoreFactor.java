package net.jdesive.secy.model.scoring;

import net.jdesive.secy.service.scoring.ScoreEffect;
import net.jdesive.secy.service.scoring.ScoreInput;

/**
 * One line of a {@link RiskScoreResult}'s breakdown — what {@code input} contributed, and the
 * running score right after it applied.
 *
 * @param input       which of the eight M1i inputs this is
 * @param effect      {@code ADD} or {@code MULTIPLY} — see {@link ScoreEffect}
 * @param value       the input value that drove this factor, rendered for display (e.g. an enum
 *                    name, a raw CVSS number, {@code "true"}/{@code "false"})
 * @param weight      the weight applied — a per-unit point value for an {@code ADD} step, a
 *                    multiplier in {@code [0,1]} for a {@code MULTIPLY} step
 * @param points      this factor's exact contribution to the final score — the running score's
 *                    rounded checkpoint after this step minus the checkpoint before it. Every
 *                    factor's {@code points} sums to the final score exactly.
 * @param runningScore the running score's rounded checkpoint after this step
 * @param available   false for {@code DEPENDENCY_DEPTH} when the component's position is
 *                     {@code UNKNOWN} (asset/scanner alert, no usable graph, unreachable from the
 *                     root, or a pre-M1l row) — see {@code RiskScorer} step 7
 * @param note        a short explanation when the value needed one (a suppression, a fallback, the
 *                    {@code DEPENDENCY_DEPTH} UNKNOWN explanation), or null
 */
public record ScoreFactor(
        ScoreInput input,
        ScoreEffect effect,
        String value,
        double weight,
        double points,
        double runningScore,
        boolean available,
        String note) {
}
