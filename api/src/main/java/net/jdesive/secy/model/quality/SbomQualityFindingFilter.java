package net.jdesive.secy.model.quality;

import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.SbomLifecycleStage;

import java.util.UUID;

/**
 * The {@code GET /sbom-quality} query string, parsed. Every field is optional. Same shape and intent
 * as {@code LifecycleDriftFilter}.
 *
 * @param productId      only findings for this product
 * @param sbomId         only findings whose representative {@code sbomId} matches
 * @param lifecycleStage exact {@link SbomLifecycleStage} (including null, for the unstaged slot)
 * @param lifecycleState defaults to {@code ACTIVE} when null
 */
public record SbomQualityFindingFilter(UUID productId, UUID sbomId, SbomLifecycleStage lifecycleStage,
                                       AlertLifecycleState lifecycleState) {

    /** The effective lifecycle state: the filter's, or {@code ACTIVE}. */
    public AlertLifecycleState effectiveLifecycleState() {
        return lifecycleState == null ? AlertLifecycleState.ACTIVE : lifecycleState;
    }

}
