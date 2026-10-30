package net.jdesive.secy.model.quality;

import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.SbomLifecycleStage;
import net.jdesive.secy.persistence.entity.SbomQualityFinding;
import net.jdesive.secy.persistence.entity.SbomQualityScore;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * One SBOM-quality finding, in full — both a row of {@code GET /sbom-quality} and the body of
 * {@code GET /sbom-quality/{id}}. Same "list and detail are the same shape" reasoning as
 * {@code LifecycleDriftFindingResponse}: there is no heavier detail to fetch separately.
 *
 * @param id              the finding id
 * @param productId       the product this slot belongs to
 * @param scopeSbomId     non-null for a bucket (Unassigned) SBOM's finding
 * @param lifecycleStage  the slot's stage, or null for the legacy unstaged slot
 * @param sbomId          the SBOM that most recently determined this finding's state
 * @param quality         a snapshot of the last low score seen for this slot
 * @param scoreThreshold  the threshold the score was compared against
 * @param summary         a one-line, human-readable statement of the completeness gap
 * @param lifecycleState  {@code ACTIVE} / {@code AUTO_RESOLVED}. Only {@code ACTIVE} rows are returned by default
 * @param createdAt       when the finding was first raised
 * @param lastSeenAt      when the reconciler last updated it
 */
public record SbomQualityFindingResponse(
        UUID id,
        UUID productId,
        UUID scopeSbomId,
        SbomLifecycleStage lifecycleStage,
        UUID sbomId,
        SbomQualityScore quality,
        Integer scoreThreshold,
        String summary,
        AlertLifecycleState lifecycleState,
        LocalDateTime createdAt,
        LocalDateTime lastSeenAt) {

    public static SbomQualityFindingResponse from(SbomQualityFinding finding) {
        return new SbomQualityFindingResponse(
                finding.getId(),
                finding.getProductId(),
                finding.getScopeSbomId(),
                finding.getLifecycleStage(),
                finding.getSbomId(),
                finding.getQuality(),
                finding.getScoreThreshold(),
                finding.getSummary(),
                finding.getLifecycleState(),
                finding.getCreatedAt(),
                finding.getLastSeenAt());
    }
}
