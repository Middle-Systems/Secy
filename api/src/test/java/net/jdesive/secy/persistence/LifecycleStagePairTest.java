package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.LifecycleStagePair;
import net.jdesive.secy.persistence.entity.SbomLifecycleStage;
import org.junit.jupiter.api.Test;

import java.util.EnumSet;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link LifecycleStagePair}: exactly the roadmap's three adjacent-stage pairs, no more. Confirms in
 * particular that Source↔Deployed and Source↔Analyzed do not exist as pairs — Build is the pivot
 * every downstream artefact is checked against, not each other.
 */
class LifecycleStagePairTest {

    @Test
    void involvingSource() {
        assertThat(LifecycleStagePair.involving(SbomLifecycleStage.SOURCE))
                .containsExactly(LifecycleStagePair.SOURCE_BUILD);
    }

    @Test
    void involvingBuildReturnsAllThree() {
        assertThat(LifecycleStagePair.involving(SbomLifecycleStage.BUILD))
                .containsExactlyInAnyOrder(LifecycleStagePair.SOURCE_BUILD, LifecycleStagePair.BUILD_DEPLOYED,
                        LifecycleStagePair.BUILD_ANALYZED);
    }

    @Test
    void involvingAnalyzed() {
        assertThat(LifecycleStagePair.involving(SbomLifecycleStage.ANALYZED))
                .containsExactly(LifecycleStagePair.BUILD_ANALYZED);
    }

    @Test
    void involvingDeployed() {
        assertThat(LifecycleStagePair.involving(SbomLifecycleStage.DEPLOYED))
                .containsExactly(LifecycleStagePair.BUILD_DEPLOYED);
    }

    @Test
    void involvingNullReturnsNone() {
        assertThat(LifecycleStagePair.involving(null)).isEmpty();
    }

    @Test
    void counterpartOf() {
        assertThat(LifecycleStagePair.SOURCE_BUILD.counterpartOf(SbomLifecycleStage.SOURCE))
                .isEqualTo(SbomLifecycleStage.BUILD);
        assertThat(LifecycleStagePair.SOURCE_BUILD.counterpartOf(SbomLifecycleStage.BUILD))
                .isEqualTo(SbomLifecycleStage.SOURCE);
        assertThat(LifecycleStagePair.SOURCE_BUILD.counterpartOf(SbomLifecycleStage.DEPLOYED)).isNull();

        assertThat(LifecycleStagePair.BUILD_DEPLOYED.counterpartOf(SbomLifecycleStage.BUILD))
                .isEqualTo(SbomLifecycleStage.DEPLOYED);
        assertThat(LifecycleStagePair.BUILD_ANALYZED.counterpartOf(SbomLifecycleStage.ANALYZED))
                .isEqualTo(SbomLifecycleStage.BUILD);
    }

    @Test
    void noSourceDeployedOrSourceAnalyzedPairExists() {
        for (LifecycleStagePair pair : LifecycleStagePair.values()) {
            EnumSet<SbomLifecycleStage> sides = EnumSet.of(pair.baseline(), pair.observed());
            boolean isSourceDeployed = sides.equals(EnumSet.of(SbomLifecycleStage.SOURCE, SbomLifecycleStage.DEPLOYED));
            boolean isSourceAnalyzed = sides.equals(EnumSet.of(SbomLifecycleStage.SOURCE, SbomLifecycleStage.ANALYZED));
            assertThat(isSourceDeployed).as("%s must not be Source/Deployed", pair).isFalse();
            assertThat(isSourceAnalyzed).as("%s must not be Source/Analyzed", pair).isFalse();
        }
        assertThat(List.of(LifecycleStagePair.values())).hasSize(3);
    }

    @Test
    void categoriesMatchTheRoadmap() {
        assertThat(LifecycleStagePair.SOURCE_BUILD.category()).isEqualTo("DEPENDENCY_CONFUSION_OR_BUILD_INJECTION");
        assertThat(LifecycleStagePair.BUILD_DEPLOYED.category()).isEqualTo("RUNTIME_DRIFT_OR_UNAUTHORIZED_CHANGE");
        assertThat(LifecycleStagePair.BUILD_ANALYZED.category()).isEqualTo("INCOMPLETE_SBOM_OR_TAMPERING");
    }

}
