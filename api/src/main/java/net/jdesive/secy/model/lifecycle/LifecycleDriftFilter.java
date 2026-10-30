package net.jdesive.secy.model.lifecycle;

import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.LifecycleDriftKind;
import net.jdesive.secy.persistence.entity.LifecycleStagePair;

import java.util.UUID;

/**
 * The {@code GET /lifecycle-drift} query string, parsed. Every field is optional. Same shape and
 * intent as {@code CompromiseFilter}.
 *
 * @param productId      only findings for this product
 * @param stagePair      exact {@link LifecycleStagePair}
 * @param driftKind      exact {@link LifecycleDriftKind}
 * @param lifecycleState defaults to {@code ACTIVE} when null
 */
public record LifecycleDriftFilter(UUID productId, LifecycleStagePair stagePair, LifecycleDriftKind driftKind,
                                   AlertLifecycleState lifecycleState) {

    /** The effective lifecycle state: the filter's, or {@code ACTIVE}. */
    public AlertLifecycleState effectiveLifecycleState() {
        return lifecycleState == null ? AlertLifecycleState.ACTIVE : lifecycleState;
    }

}
