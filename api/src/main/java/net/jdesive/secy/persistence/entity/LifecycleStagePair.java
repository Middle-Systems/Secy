package net.jdesive.secy.persistence.entity;

import java.util.List;

/**
 * The three adjacent-stage pairs M1e diffs (ROADMAP.md, M1e — "SBOM lifecycle stages + diffing").
 *
 * <p>These are <b>exactly</b> the roadmap's three pairs — {@code Source} vs {@code Build},
 * {@code Build} vs {@code Deployed}, {@code Build} vs {@code Analyzed}. Source↔Deployed and
 * Source↔Analyzed are <b>deliberately not compared</b>: {@code Build} is the pivot every downstream
 * artefact is checked against, not each other, so a Source/Deployed disagreement is expected to
 * flow through the Build comparison instead of being raised twice.
 */
public enum LifecycleStagePair {

    SOURCE_BUILD(SbomLifecycleStage.SOURCE, SbomLifecycleStage.BUILD, "DEPENDENCY_CONFUSION_OR_BUILD_INJECTION"),
    BUILD_DEPLOYED(SbomLifecycleStage.BUILD, SbomLifecycleStage.DEPLOYED, "RUNTIME_DRIFT_OR_UNAUTHORIZED_CHANGE"),
    BUILD_ANALYZED(SbomLifecycleStage.BUILD, SbomLifecycleStage.ANALYZED, "INCOMPLETE_SBOM_OR_TAMPERING");

    private final SbomLifecycleStage baseline;
    private final SbomLifecycleStage observed;
    private final String category;

    LifecycleStagePair(SbomLifecycleStage baseline, SbomLifecycleStage observed, String category) {
        this.baseline = baseline;
        this.observed = observed;
        this.category = category;
    }

    /** The upstream stage in this pair — what the downstream stage is checked against. */
    public SbomLifecycleStage baseline() {
        return baseline;
    }

    /** The downstream stage in this pair — what is checked for unvouched-for content. */
    public SbomLifecycleStage observed() {
        return observed;
    }

    /** The finding category string surfaced on {@code LifecycleDriftFindingResponse}. */
    public String category() {
        return category;
    }

    /**
     * The pair(s) a diff run for {@code stage} should evaluate.
     *
     * <ul>
     *   <li>{@code SOURCE} → [{@code SOURCE_BUILD}]</li>
     *   <li>{@code BUILD} → all three (it is the pivot of every pair)</li>
     *   <li>{@code ANALYZED} → [{@code BUILD_ANALYZED}]</li>
     *   <li>{@code DEPLOYED} → [{@code BUILD_DEPLOYED}]</li>
     *   <li>{@code null} → none</li>
     * </ul>
     */
    public static List<LifecycleStagePair> involving(SbomLifecycleStage stage) {
        if (stage == null) {
            return List.of();
        }
        return switch (stage) {
            case SOURCE -> List.of(SOURCE_BUILD);
            case BUILD -> List.of(SOURCE_BUILD, BUILD_DEPLOYED, BUILD_ANALYZED);
            case ANALYZED -> List.of(BUILD_ANALYZED);
            case DEPLOYED -> List.of(BUILD_DEPLOYED);
        };
    }

    /** The other stage in this pair, given one side of it — null if {@code stage} is neither side. */
    public SbomLifecycleStage counterpartOf(SbomLifecycleStage stage) {
        if (stage == baseline) {
            return observed;
        }
        if (stage == observed) {
            return baseline;
        }
        return null;
    }
}
