package net.jdesive.secy.service.scoring;

import net.jdesive.secy.model.scoring.RiskScoreResult;
import net.jdesive.secy.model.scoring.ScoreFactor;
import net.jdesive.secy.persistence.entity.DependencyDepth;
import net.jdesive.secy.persistence.entity.ExploitMaturity;
import net.jdesive.secy.persistence.entity.FixState;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.offset;

/**
 * Pins the M1i formula (ROADMAP.md — "Scoring engine rework", §3) against the plan's own worked
 * examples, so a future weights change has to consciously break these numbers rather than drift.
 */
class RiskScorerTest {

    private static final double EPS = 0.0001;

    /* ------------------------------------------------------------------ */
    /* Worked examples                                                     */
    /* ------------------------------------------------------------------ */

    @Test
    void deployedProductWorkedExample() {
        RiskScoreInputs inputs = new RiskScoreInputs(9.8, null, true, 0.94, ExploitMaturity.IN_THE_WILD,
                LifecyclePresence.DEPLOYED, VexScoringState.NONE, DependencyDepth.UNKNOWN, FixState.FIXED);

        RiskScoreResult result = RiskScorer.score(inputs, ScoringWeights.DEFAULT);

        assertThat(result.score()).isCloseTo(92.8, offset(EPS));
        assertThat(result.model()).isEqualTo("m1i.1");

        List<ScoreFactor> f = result.factors();
        assertThat(f).hasSize(8);
        assertFactor(f.get(0), ScoreInput.CVSS_BASE, ScoreEffect.ADD, 39.2, 39.2, true);
        assertFactor(f.get(1), ScoreInput.KEV, ScoreEffect.ADD, 35.0, 74.2, true);
        assertFactor(f.get(2), ScoreInput.EPSS, ScoreEffect.ADD, 23.5, 97.7, true);
        assertFactor(f.get(3), ScoreInput.EXPLOIT_MATURITY, ScoreEffect.ADD, 0.0, 97.7, true);
        assertThat(f.get(3).note()).isEqualTo("already counted by KEV");
        assertFactor(f.get(4), ScoreInput.LIFECYCLE_PRESENCE, ScoreEffect.MULTIPLY, 0.0, 97.7, true);
        assertFactor(f.get(5), ScoreInput.VEX_STATUS, ScoreEffect.MULTIPLY, 0.0, 97.7, true);
        assertFactor(f.get(6), ScoreInput.DEPENDENCY_DEPTH, ScoreEffect.MULTIPLY, 0.0, 97.7, false);
        assertFactor(f.get(7), ScoreInput.FIX_AVAILABILITY, ScoreEffect.MULTIPLY, -4.9, 92.8, true);

        assertTelescopes(f, 92.8);
    }

    @Test
    void sourceOnlyProductWorkedExample() {
        RiskScoreInputs inputs = new RiskScoreInputs(9.8, null, true, 0.94, ExploitMaturity.IN_THE_WILD,
                LifecyclePresence.SOURCE, VexScoringState.NONE, DependencyDepth.UNKNOWN, FixState.FIXED);

        RiskScoreResult result = RiskScorer.score(inputs, ScoringWeights.DEFAULT);

        assertThat(result.score()).isCloseTo(55.7, offset(EPS));
        List<ScoreFactor> f = result.factors();
        assertFactor(f.get(4), ScoreInput.LIFECYCLE_PRESENCE, ScoreEffect.MULTIPLY, -39.1, 58.6, true);
        assertThat(f.get(4).value()).isEqualTo("SOURCE");
        assertThat(f.get(4).weight()).isCloseTo(0.6, offset(EPS));
        assertFactor(f.get(7), ScoreInput.FIX_AVAILABILITY, ScoreEffect.MULTIPLY, -2.9, 55.7, true);

        assertTelescopes(f, 55.7);
    }

    /* ------------------------------------------------------------------ */
    /* Maxima                                                              */
    /* ------------------------------------------------------------------ */

    @Test
    void kevPathMaxesAtExactlyOneHundred() {
        RiskScoreInputs inputs = new RiskScoreInputs(10.0, null, true, 1.0, ExploitMaturity.IN_THE_WILD,
                LifecyclePresence.DEPLOYED, VexScoringState.NONE, DependencyDepth.UNKNOWN, FixState.UNKNOWN);

        RiskScoreResult result = RiskScorer.score(inputs, ScoringWeights.DEFAULT);

        assertThat(result.score()).isCloseTo(100.0, offset(EPS));
        assertThat(result.factors().get(3).points()).isCloseTo(0.0, offset(EPS));
        assertThat(result.factors().get(3).note()).isEqualTo("already counted by KEV");
    }

    @Test
    void nonKevMaxIsEighty() {
        RiskScoreInputs inputs = new RiskScoreInputs(10.0, null, false, 1.0, ExploitMaturity.IN_THE_WILD,
                LifecyclePresence.DEPLOYED, VexScoringState.NONE, DependencyDepth.UNKNOWN, FixState.UNKNOWN);

        RiskScoreResult result = RiskScorer.score(inputs, ScoringWeights.DEFAULT);

        assertThat(result.score()).isCloseTo(80.0, offset(EPS));
        assertThat(result.factors().get(3).points()).isCloseTo(15.0, offset(EPS));
        assertThat(result.factors().get(3).note()).isNull();
    }

    /* ------------------------------------------------------------------ */
    /* VEX                                                                 */
    /* ------------------------------------------------------------------ */

    @Test
    void vexNotAffectedOrFixedZeroTheScoreButKeepEarlierFactorsVisible() {
        RiskScoreInputs base = new RiskScoreInputs(9.0, null, false, 0.5, ExploitMaturity.NONE,
                LifecyclePresence.DEPLOYED, VexScoringState.NOT_AFFECTED, DependencyDepth.UNKNOWN, FixState.UNKNOWN);
        RiskScoreResult result = RiskScorer.score(base, ScoringWeights.DEFAULT);
        assertThat(result.score()).isCloseTo(0.0, offset(EPS));
        // The pre-VEX running score is still visible on the EPSS factor.
        assertThat(result.factors().get(2).runningScore()).isGreaterThan(0.0);
        assertThat(result.factors().get(5).points()).isLessThan(0.0);

        RiskScoreInputs fixed = new RiskScoreInputs(9.0, null, false, 0.5, ExploitMaturity.NONE,
                LifecyclePresence.DEPLOYED, VexScoringState.FIXED, DependencyDepth.UNKNOWN, FixState.UNKNOWN);
        assertThat(RiskScorer.score(fixed, ScoringWeights.DEFAULT).score()).isCloseTo(0.0, offset(EPS));
    }

    @Test
    void vexConflictAffectedAndUnderInvestigationAreNeutral() {
        for (VexScoringState state : List.of(VexScoringState.CONFLICT, VexScoringState.AFFECTED,
                VexScoringState.UNDER_INVESTIGATION, VexScoringState.NONE)) {
            RiskScoreInputs inputs = new RiskScoreInputs(9.0, null, false, 0.5, ExploitMaturity.NONE,
                    LifecyclePresence.DEPLOYED, state, DependencyDepth.UNKNOWN, FixState.UNKNOWN);
            RiskScoreResult result = RiskScorer.score(inputs, ScoringWeights.DEFAULT);
            assertThat(result.factors().get(5).points()).as("state=%s", state).isCloseTo(0.0, offset(EPS));
        }
    }

    /* ------------------------------------------------------------------ */
    /* CVSS fallback                                                       */
    /* ------------------------------------------------------------------ */

    @Test
    void cvssFallsBackToSeverityBandThenToUnknown() {
        RiskScoreInputs bandOnly = new RiskScoreInputs(null, "HIGH", false, null, ExploitMaturity.NONE,
                LifecyclePresence.STAGE_UNKNOWN, VexScoringState.NONE, DependencyDepth.UNKNOWN, FixState.UNKNOWN);
        ScoreFactor bandFactor = RiskScorer.score(bandOnly, ScoringWeights.DEFAULT).factors().get(0);
        assertThat(bandFactor.points()).isCloseTo(32.0, offset(EPS));
        assertThat(bandFactor.value()).isEqualTo("HIGH");
        assertThat(bandFactor.note()).contains("HIGH");

        RiskScoreInputs bothNull = new RiskScoreInputs(null, null, false, null, ExploitMaturity.NONE,
                LifecyclePresence.STAGE_UNKNOWN, VexScoringState.NONE, DependencyDepth.UNKNOWN, FixState.UNKNOWN);
        ScoreFactor unknownFactor = RiskScorer.score(bothNull, ScoringWeights.DEFAULT).factors().get(0);
        assertThat(unknownFactor.points()).isCloseTo(20.0, offset(EPS));
        assertThat(unknownFactor.value()).isEqualTo("UNKNOWN");
    }

    /* ------------------------------------------------------------------ */
    /* Dependency depth                                                    */
    /* ------------------------------------------------------------------ */

    @Test
    void dependencyDepthDirectEqualsUnknownTransitiveDiscounts() {
        RiskScoreInputs direct = fixedInputsWithDepth(DependencyDepth.DIRECT);
        RiskScoreInputs unknown = fixedInputsWithDepth(DependencyDepth.UNKNOWN);
        RiskScoreInputs transitive = fixedInputsWithDepth(DependencyDepth.TRANSITIVE);

        double directScore = RiskScorer.score(direct, ScoringWeights.DEFAULT).score();
        double unknownScore = RiskScorer.score(unknown, ScoringWeights.DEFAULT).score();
        double transitiveScore = RiskScorer.score(transitive, ScoringWeights.DEFAULT).score();

        assertThat(directScore).isCloseTo(unknownScore, offset(EPS));
        assertThat(transitiveScore).isLessThan(directScore);
        assertThat(directScore - transitiveScore).isCloseTo(directScore * 0.1, offset(0.5));
    }

    private RiskScoreInputs fixedInputsWithDepth(DependencyDepth depth) {
        return new RiskScoreInputs(9.0, null, false, 0.5, ExploitMaturity.NONE,
                LifecyclePresence.DEPLOYED, VexScoringState.NONE, depth, FixState.UNKNOWN);
    }

    /* ------------------------------------------------------------------ */
    /* Lifecycle ordering                                                  */
    /* ------------------------------------------------------------------ */

    @Test
    void lifecyclePresenceOrdering() {
        double deployed = scoreWithLifecycle(LifecyclePresence.DEPLOYED);
        double stageUnknown = scoreWithLifecycle(LifecyclePresence.STAGE_UNKNOWN);
        double assetObserved = scoreWithLifecycle(LifecyclePresence.ASSET_OBSERVED);
        double analyzed = scoreWithLifecycle(LifecyclePresence.ANALYZED);
        double build = scoreWithLifecycle(LifecyclePresence.BUILD);
        double source = scoreWithLifecycle(LifecyclePresence.SOURCE);

        assertThat(deployed).isCloseTo(stageUnknown, offset(EPS));
        assertThat(stageUnknown).isCloseTo(assetObserved, offset(EPS));
        assertThat(deployed).isGreaterThan(analyzed);
        assertThat(analyzed).isGreaterThan(build);
        assertThat(build).isGreaterThan(source);
    }

    private double scoreWithLifecycle(LifecyclePresence presence) {
        RiskScoreInputs inputs = new RiskScoreInputs(9.0, null, false, 0.5, ExploitMaturity.NONE,
                presence, VexScoringState.NONE, DependencyDepth.UNKNOWN, FixState.UNKNOWN);
        return RiskScorer.score(inputs, ScoringWeights.DEFAULT).score();
    }

    /* ------------------------------------------------------------------ */
    /* Fix availability                                                    */
    /* ------------------------------------------------------------------ */

    @Test
    void fixAvailabilityDiscountsOnlyFixed() {
        double fixed = scoreWithFix(FixState.FIXED);
        double noFix = scoreWithFix(FixState.NO_FIX);
        double unknown = scoreWithFix(FixState.UNKNOWN);
        double nullFix = RiskScorer.score(new RiskScoreInputs(9.0, null, false, 0.5, ExploitMaturity.NONE,
                LifecyclePresence.DEPLOYED, VexScoringState.NONE, DependencyDepth.UNKNOWN, null), ScoringWeights.DEFAULT).score();

        assertThat(noFix).isCloseTo(unknown, offset(EPS));
        assertThat(unknown).isCloseTo(nullFix, offset(EPS));
        assertThat(fixed).isLessThan(noFix);
    }

    private double scoreWithFix(FixState fixState) {
        RiskScoreInputs inputs = new RiskScoreInputs(9.0, null, false, 0.5, ExploitMaturity.NONE,
                LifecyclePresence.DEPLOYED, VexScoringState.NONE, DependencyDepth.UNKNOWN, fixState);
        return RiskScorer.score(inputs, ScoringWeights.DEFAULT).score();
    }

    /* ------------------------------------------------------------------ */
    /* All-null input                                                      */
    /* ------------------------------------------------------------------ */

    @Test
    void allNullInputStillProducesAWellFormedEightFactorBreakdown() {
        RiskScoreInputs inputs = new RiskScoreInputs(null, null, false, null, null, null, null, null, null);
        RiskScoreResult result = RiskScorer.score(inputs, ScoringWeights.DEFAULT);

        assertThat(result.factors()).hasSize(8);
        assertThat(result.factors()).extracting(ScoreFactor::input)
                .containsExactly(ScoreInput.values());
        // CVSS unknown (20.0) is the only non-zero additive contribution; every multiplier is neutral.
        assertThat(result.score()).isCloseTo(20.0, offset(EPS));
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                             */
    /* ------------------------------------------------------------------ */

    private static void assertFactor(ScoreFactor factor, ScoreInput input, ScoreEffect effect,
                                     double points, double runningScore, boolean available) {
        assertThat(factor.input()).isEqualTo(input);
        assertThat(factor.effect()).isEqualTo(effect);
        assertThat(factor.points()).as("%s points", input).isCloseTo(points, offset(EPS));
        assertThat(factor.runningScore()).as("%s runningScore", input).isCloseTo(runningScore, offset(EPS));
        assertThat(factor.available()).isEqualTo(available);
    }

    private static void assertTelescopes(List<ScoreFactor> factors, double expectedScore) {
        double sum = factors.stream().mapToDouble(ScoreFactor::points).sum();
        assertThat(sum).isCloseTo(expectedScore, offset(EPS));
    }

}
