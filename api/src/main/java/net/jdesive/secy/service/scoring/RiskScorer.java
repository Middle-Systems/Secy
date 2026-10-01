package net.jdesive.secy.service.scoring;

import net.jdesive.secy.model.scoring.RiskScoreResult;
import net.jdesive.secy.model.scoring.ScoreFactor;
import net.jdesive.secy.persistence.entity.DependencyDepth;
import net.jdesive.secy.persistence.entity.ExploitMaturity;
import net.jdesive.secy.persistence.entity.FixState;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * The M1i risk-scoring formula (ROADMAP.md — "Scoring engine rework") — a pure function of
 * {@link RiskScoreInputs} and {@link ScoringWeights}, no Spring/JPA, following the same pure-scorer
 * pattern as M1c/M1h.
 *
 * <h2>Arithmetic</h2>
 *
 * <p>The running score starts at {@code 0} and is carried as an unrounded {@link BigDecimal} through
 * all eight {@link ScoreInput} steps, in declaration order. An {@code ADD} step adds points and then
 * clamps the running value to {@code [0, 100]}; a {@code MULTIPLY} step multiplies it (weights are
 * validated into {@code [0, 1]}, so no clamp is needed after). After each step a <em>checkpoint</em>
 * — the running value rounded to one decimal, {@link RoundingMode#HALF_UP} — is taken for reporting;
 * that checkpoint is never fed back into the unrounded running value, only used to compute the
 * factor's reported {@code points} as {@code checkpoint_i - checkpoint_{i-1}}. Because every factor's
 * points are a telescoping difference of the same checkpoint sequence, they always sum to the final
 * score exactly, regardless of any rounding along the way.
 */
public final class RiskScorer {

    private static final BigDecimal ZERO = BigDecimal.ZERO;
    private static final BigDecimal HUNDRED = BigDecimal.valueOf(100);

    private RiskScorer() {
    }

    public static RiskScoreResult score(RiskScoreInputs inputs, ScoringWeights weights) {
        List<ScoreFactor> factors = new ArrayList<>(ScoreInput.values().length);
        BigDecimal running = ZERO;
        BigDecimal checkpoint = checkpointOf(running);

        // 1. CVSS_BASE (ADD)
        CvssContribution cvss = cvssContribution(inputs, weights);
        running = clamp(running.add(cvss.points()));
        checkpoint = addFactor(factors, ScoreInput.CVSS_BASE, ScoreEffect.ADD, cvss.value(),
                weights.cvssPointsPerUnit(), running, checkpoint, true, cvss.note());

        // 2. KEV (ADD)
        BigDecimal kevPoints = inputs.kevListed() ? BigDecimal.valueOf(weights.kevPoints()) : ZERO;
        running = clamp(running.add(kevPoints));
        checkpoint = addFactor(factors, ScoreInput.KEV, ScoreEffect.ADD, String.valueOf(inputs.kevListed()),
                weights.kevPoints(), running, checkpoint, true, null);

        // 3. EPSS (ADD) -- raw probability, null counts as 0.
        double epss = inputs.epssScore() == null ? 0.0d : inputs.epssScore();
        BigDecimal epssPoints = BigDecimal.valueOf(weights.epssMaxPoints()).multiply(BigDecimal.valueOf(epss));
        running = clamp(running.add(epssPoints));
        checkpoint = addFactor(factors, ScoreInput.EPSS, ScoreEffect.ADD,
                inputs.epssScore() == null ? "0.0" : String.valueOf(inputs.epssScore()),
                weights.epssMaxPoints(), running, checkpoint, true, null);

        // 4. EXPLOIT_MATURITY (ADD) -- suppressed to 0 when KEV-listed (KEV implies IN_THE_WILD).
        ExploitMaturity maturity = inputs.exploitMaturity() == null ? ExploitMaturity.NONE : inputs.exploitMaturity();
        double maturityWeight = weights.exploitMaturityPoints().get(maturity);
        boolean suppressed = inputs.kevListed();
        BigDecimal maturityPoints = suppressed ? ZERO : BigDecimal.valueOf(maturityWeight);
        running = clamp(running.add(maturityPoints));
        checkpoint = addFactor(factors, ScoreInput.EXPLOIT_MATURITY, ScoreEffect.ADD, maturity.name(),
                maturityWeight, running, checkpoint, true, suppressed ? "already counted by KEV" : null);

        // 5. LIFECYCLE_PRESENCE (MULTIPLY)
        LifecyclePresence lifecycle = inputs.lifecycle() == null ? LifecyclePresence.STAGE_UNKNOWN : inputs.lifecycle();
        double lifecycleWeight = weights.lifecycleFactor().get(lifecycle);
        running = running.multiply(BigDecimal.valueOf(lifecycleWeight));
        checkpoint = addFactor(factors, ScoreInput.LIFECYCLE_PRESENCE, ScoreEffect.MULTIPLY, lifecycle.name(),
                lifecycleWeight, running, checkpoint, true, null);

        // 6. VEX_STATUS (MULTIPLY)
        VexScoringState vex = inputs.vex() == null ? VexScoringState.NONE : inputs.vex();
        double vexWeight = weights.vexFactor().get(vex);
        running = running.multiply(BigDecimal.valueOf(vexWeight));
        checkpoint = addFactor(factors, ScoreInput.VEX_STATUS, ScoreEffect.MULTIPLY, vex.name(),
                vexWeight, running, checkpoint, true, null);

        // 7. DEPENDENCY_DEPTH (MULTIPLY) -- M1l: a real DIRECT/TRANSITIVE/UNKNOWN value now reaches
        // here (RiskScoreInputs.dependencyDepthOf); `available` reflects whether this alert's
        // component actually had a classifiable position, not a blanket "not yet tracked".
        DependencyDepth depth = inputs.depth() == null ? DependencyDepth.UNKNOWN : inputs.depth();
        double depthWeight = weights.dependencyDepthFactor().get(depth);
        running = running.multiply(BigDecimal.valueOf(depthWeight));
        boolean depthAvailable = depth != DependencyDepth.UNKNOWN;
        String depthNote = depthAvailable ? null
                : "Not known for this component — asset/scanner finding, no usable dependency graph "
                        + "in the SBOM, component unreachable from the root, or ingested before M1l. Neutral.";
        checkpoint = addFactor(factors, ScoreInput.DEPENDENCY_DEPTH, ScoreEffect.MULTIPLY, depth.name(),
                depthWeight, running, checkpoint, depthAvailable, depthNote);

        // 8. FIX_AVAILABILITY (MULTIPLY)
        FixState fixState = inputs.fixState() == null ? FixState.UNKNOWN : inputs.fixState();
        double fixWeight = weights.fixFactor().get(fixState);
        running = running.multiply(BigDecimal.valueOf(fixWeight));
        checkpoint = addFactor(factors, ScoreInput.FIX_AVAILABILITY, ScoreEffect.MULTIPLY, fixState.name(),
                fixWeight, running, checkpoint, true, null);

        return new RiskScoreResult(checkpoint.doubleValue(), weights.modelVersion(), List.copyOf(factors));
    }

    /** Appends one {@link ScoreFactor} and returns the new checkpoint, so callers can chain. */
    private static BigDecimal addFactor(List<ScoreFactor> factors, ScoreInput input, ScoreEffect effect,
                                        String value, double weight, BigDecimal running, BigDecimal previousCheckpoint,
                                        boolean available, String note) {
        BigDecimal newCheckpoint = checkpointOf(running);
        double points = newCheckpoint.subtract(previousCheckpoint).doubleValue();
        factors.add(new ScoreFactor(input, effect, value, weight, points, newCheckpoint.doubleValue(), available, note));
        return newCheckpoint;
    }

    private static BigDecimal checkpointOf(BigDecimal value) {
        return value.setScale(1, RoundingMode.HALF_UP);
    }

    private static BigDecimal clamp(BigDecimal value) {
        if (value.compareTo(ZERO) < 0) {
            return ZERO;
        }
        if (value.compareTo(HUNDRED) > 0) {
            return HUNDRED;
        }
        return value;
    }

    private record CvssContribution(BigDecimal points, String value, String note) {
    }

    /**
     * {@code alert.cvssScore} first; failing that, {@code alert.vulnerability.baseSeverity}'s band
     * value; failing that, {@link ScoringWeights#unknownCvss()} — "unknown is not harmless".
     */
    private static CvssContribution cvssContribution(RiskScoreInputs inputs, ScoringWeights weights) {
        BigDecimal perUnit = BigDecimal.valueOf(weights.cvssPointsPerUnit());
        if (inputs.cvssScore() != null) {
            BigDecimal raw = BigDecimal.valueOf(inputs.cvssScore());
            return new CvssContribution(raw.multiply(perUnit), String.valueOf(inputs.cvssScore()), null);
        }
        if (inputs.baseSeverity() != null) {
            String band = inputs.baseSeverity().toUpperCase(Locale.ROOT);
            Double bandValue = weights.severityBandCvss().get(band);
            if (bandValue != null) {
                BigDecimal raw = BigDecimal.valueOf(bandValue);
                return new CvssContribution(raw.multiply(perUnit), band,
                        "No CVSS score; using the " + band + " severity band (" + bandValue + ")");
            }
        }
        BigDecimal raw = BigDecimal.valueOf(weights.unknownCvss());
        return new CvssContribution(raw.multiply(perUnit), "UNKNOWN",
                "No CVSS score or recognised severity band; treating as medium (" + weights.unknownCvss()
                        + ") — unknown is not harmless");
    }

}
