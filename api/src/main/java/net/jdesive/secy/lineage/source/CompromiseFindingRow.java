package net.jdesive.secy.lineage.source;

import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.CompromiseConfidence;
import net.jdesive.secy.persistence.entity.CompromiseType;
import net.jdesive.secy.persistence.entity.TriageState;

import java.util.UUID;

/**
 * One {@code CompromiseFinding} row, as read for lineage planning. Exactly one of
 * {@code componentId}/{@code assetComponentId} is non-null (the entity's own XOR invariant).
 */
public record CompromiseFindingRow(UUID id, UUID componentId, UUID assetComponentId, CompromiseType type,
                                    CompromiseConfidence confidence, String severity, String source,
                                    String iocId, AlertLifecycleState lifecycleState, TriageState triageState) {
}
