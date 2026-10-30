package net.jdesive.secy.service.scoring;

import net.jdesive.secy.persistence.entity.DependencyDepth;
import net.jdesive.secy.persistence.entity.ExploitMaturity;
import net.jdesive.secy.persistence.entity.FixState;
import org.junit.jupiter.api.Test;

import java.util.EnumMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ScoringWeightsTest {

    @Test
    void defaultCoversEveryEnumConstantAndValidates() {
        ScoringWeights weights = ScoringWeights.DEFAULT;
        assertThat(weights.modelVersion()).isEqualTo("m1i.1");
        for (ExploitMaturity m : ExploitMaturity.values()) {
            assertThat(weights.exploitMaturityPoints()).containsKey(m);
        }
        for (LifecyclePresence p : LifecyclePresence.values()) {
            assertThat(weights.lifecycleFactor()).containsKey(p);
        }
        assertThat(weights.lifecycleFactor().get(LifecyclePresence.SOURCE)).isEqualTo(0.6);
        for (VexScoringState v : VexScoringState.values()) {
            assertThat(weights.vexFactor()).containsKey(v);
        }
        for (DependencyDepth d : DependencyDepth.values()) {
            assertThat(weights.dependencyDepthFactor()).containsKey(d);
        }
        for (FixState f : FixState.values()) {
            assertThat(weights.fixFactor()).containsKey(f);
        }
        for (String band : new String[]{"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}) {
            assertThat(weights.severityBandCvss()).containsKey(band);
        }
    }

    @Test
    void missingEnumEntryThrows() {
        Map<ExploitMaturity, Double> incomplete = new EnumMap<>(ExploitMaturity.class);
        incomplete.put(ExploitMaturity.NONE, 0.0);
        incomplete.put(ExploitMaturity.POC, 5.0);
        incomplete.put(ExploitMaturity.WEAPONIZED, 10.0);
        // IN_THE_WILD deliberately missing.

        assertThatThrownBy(() -> new ScoringWeights(
                "m1i.1", 4.0, ScoringWeights.DEFAULT.severityBandCvss(), 5.0, 35.0, 25.0,
                incomplete, ScoringWeights.DEFAULT.lifecycleFactor(), ScoringWeights.DEFAULT.vexFactor(),
                ScoringWeights.DEFAULT.dependencyDepthFactor(), ScoringWeights.DEFAULT.fixFactor()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void multiplierAboveOneThrows() {
        Map<LifecyclePresence, Double> bad = new EnumMap<>(ScoringWeights.DEFAULT.lifecycleFactor());
        bad.put(LifecyclePresence.SOURCE, 1.5);

        assertThatThrownBy(() -> new ScoringWeights(
                "m1i.1", 4.0, ScoringWeights.DEFAULT.severityBandCvss(), 5.0, 35.0, 25.0,
                ScoringWeights.DEFAULT.exploitMaturityPoints(), bad, ScoringWeights.DEFAULT.vexFactor(),
                ScoringWeights.DEFAULT.dependencyDepthFactor(), ScoringWeights.DEFAULT.fixFactor()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void negativeAdditiveWeightThrows() {
        assertThatThrownBy(() -> new ScoringWeights(
                "m1i.1", 4.0, ScoringWeights.DEFAULT.severityBandCvss(), 5.0, -1.0, 25.0,
                ScoringWeights.DEFAULT.exploitMaturityPoints(), ScoringWeights.DEFAULT.lifecycleFactor(),
                ScoringWeights.DEFAULT.vexFactor(), ScoringWeights.DEFAULT.dependencyDepthFactor(),
                ScoringWeights.DEFAULT.fixFactor()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void blankModelVersionThrows() {
        assertThatThrownBy(() -> new ScoringWeights(
                " ", 4.0, ScoringWeights.DEFAULT.severityBandCvss(), 5.0, 35.0, 25.0,
                ScoringWeights.DEFAULT.exploitMaturityPoints(), ScoringWeights.DEFAULT.lifecycleFactor(),
                ScoringWeights.DEFAULT.vexFactor(), ScoringWeights.DEFAULT.dependencyDepthFactor(),
                ScoringWeights.DEFAULT.fixFactor()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void missingSeverityBandThrows() {
        Map<String, Double> incomplete = Map.of("NONE", 0.0, "LOW", 2.0, "MEDIUM", 5.5, "HIGH", 8.0);
        assertThatThrownBy(() -> new ScoringWeights(
                "m1i.1", 4.0, incomplete, 5.0, 35.0, 25.0,
                ScoringWeights.DEFAULT.exploitMaturityPoints(), ScoringWeights.DEFAULT.lifecycleFactor(),
                ScoringWeights.DEFAULT.vexFactor(), ScoringWeights.DEFAULT.dependencyDepthFactor(),
                ScoringWeights.DEFAULT.fixFactor()))
                .isInstanceOf(IllegalArgumentException.class);
    }

}
