package net.jdesive.secy.lineage.source;

import net.jdesive.secy.persistence.entity.SbomIngestionSource;
import net.jdesive.secy.persistence.entity.SbomLifecycleStage;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * One active {@code SBOM} row, as read for lineage planning. {@code productId} is null for an
 * SBOM with no product link (should not happen in practice — every SBOM belongs to a product or
 * the Unassigned bucket — but the field is nullable on the entity, so it is nullable here too).
 */
public record SbomRow(UUID id, UUID productId, String format, String specVersion, int version,
                       String productVersion, String status, LocalDateTime uploadDate,
                       SbomIngestionSource ingestionSource, UUID sourceConnectorId,
                       SbomLifecycleStage lifecycleStage) {
}
