package net.jdesive.secy.model.lifecycle;

import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.LifecycleDriftFinding;
import net.jdesive.secy.persistence.entity.LifecycleDriftKind;
import net.jdesive.secy.persistence.entity.LifecycleStagePair;
import net.jdesive.secy.persistence.entity.SbomLifecycleStage;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * One lifecycle drift finding, in full — both a row of {@code GET /lifecycle-drift} and the body of
 * {@code GET /lifecycle-drift/{id}}. Same "list and detail are the same shape" reasoning as
 * {@code CompromiseFindingResponse}: there is no heavier detail to fetch separately.
 *
 * @param id                  the finding id
 * @param productId           the product this pair of SBOMs belongs to
 * @param stagePair           which adjacent pair this disagreement was found between
 * @param baselineStage       {@link LifecycleStagePair#baseline()} of {@link #stagePair} — the upstream stage
 * @param observedStage       {@link LifecycleStagePair#observed()} of {@link #stagePair} — the downstream stage
 * @param category            {@link LifecycleStagePair#category()} of {@link #stagePair}
 * @param driftKind           {@code UNEXPECTED_COMPONENT} or {@code VERSION_MISMATCH}
 * @param identityKey         the component identity this finding is about
 * @param componentName       the representative component's declared name
 * @param componentPurl       the representative component's declared PURL, when it has one
 * @param observedVersion     distinct, sorted, comma-joined concrete versions seen downstream
 * @param baselineVersion     same shape, from the baseline SBOM — null for {@code UNEXPECTED_COMPONENT}
 * @param baselineSbomId      the upstream SBOM in this pair
 * @param observedSbomId      the downstream SBOM in this pair
 * @param observedComponentId the representative {@code sbom_component} row in the observed SBOM, when one exists
 * @param summary             a one-line, human-readable statement of the disagreement
 * @param lifecycleState      {@code ACTIVE} / {@code AUTO_RESOLVED}. Only {@code ACTIVE} rows are returned by default
 * @param createdAt           when the finding was first raised
 * @param lastSeenAt          when the diff engine last reproduced it
 */
public record LifecycleDriftFindingResponse(
        UUID id,
        UUID productId,
        LifecycleStagePair stagePair,
        SbomLifecycleStage baselineStage,
        SbomLifecycleStage observedStage,
        String category,
        LifecycleDriftKind driftKind,
        String identityKey,
        String componentName,
        String componentPurl,
        String observedVersion,
        String baselineVersion,
        UUID baselineSbomId,
        UUID observedSbomId,
        UUID observedComponentId,
        String summary,
        AlertLifecycleState lifecycleState,
        LocalDateTime createdAt,
        LocalDateTime lastSeenAt) {

    public static LifecycleDriftFindingResponse from(LifecycleDriftFinding finding) {
        LifecycleStagePair pair = finding.getStagePair();
        return new LifecycleDriftFindingResponse(
                finding.getId(),
                finding.getProductId(),
                pair,
                pair == null ? null : pair.baseline(),
                pair == null ? null : pair.observed(),
                pair == null ? null : pair.category(),
                finding.getDriftKind(),
                finding.getIdentityKey(),
                finding.getComponentName(),
                finding.getComponentPurl(),
                finding.getObservedVersion(),
                finding.getBaselineVersion(),
                finding.getBaselineSbomId(),
                finding.getObservedSbomId(),
                finding.getObservedComponentId(),
                finding.getSummary(),
                finding.getLifecycleState(),
                finding.getCreatedAt(),
                finding.getLastSeenAt());
    }
}
