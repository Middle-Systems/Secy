package net.jdesive.secy.model.compromise;

import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.CompromiseConfidence;
import net.jdesive.secy.persistence.entity.CompromiseType;

import java.util.UUID;

/**
 * The {@code GET /compromise} query string, parsed. Every field is optional.
 *
 * @param type           exact {@link CompromiseType}
 * @param confidence     exact {@link CompromiseConfidence}. Exact rather than "at or above" for the
 *                       same reason {@code ActionableFilter.matchConfidence} is: the useful question
 *                       in practice is the band, and "show me only what has decayed" is as real a
 *                       question as "show me only what is confirmed"
 * @param productId      only findings on SBOMs belonging to this product
 * @param assetId        only findings on this asset's components
 * @param componentId    a single component, of either kind — matched against both
 *                       {@code component_id} and {@code asset_component_id}, so a caller holding a
 *                       component id from the {@code /actionable} row does not need to know which
 *                       kind it is
 * @param lifecycleState defaults to {@code ACTIVE} when null. Pass {@code AUTO_RESOLVED} to see what
 *                       a re-scan stopped reproducing — kept, never deleted, so it is always there
 *                       to ask for
 */
public record CompromiseFilter(
        CompromiseType type,
        CompromiseConfidence confidence,
        UUID productId,
        UUID assetId,
        UUID componentId,
        AlertLifecycleState lifecycleState) {

    /** The effective lifecycle state: the filter's, or {@code ACTIVE}. */
    public AlertLifecycleState effectiveLifecycleState() {
        return lifecycleState == null ? AlertLifecycleState.ACTIVE : lifecycleState;
    }

}
