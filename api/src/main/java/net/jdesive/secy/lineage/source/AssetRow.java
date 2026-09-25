package net.jdesive.secy.lineage.source;

import net.jdesive.secy.persistence.entity.AssetType;

import java.time.LocalDateTime;
import java.util.UUID;

/** One {@code Asset} row, as read for lineage planning. {@code productId} is nullable — see {@code Asset}. */
public record AssetRow(UUID id, UUID productId, AssetType type, String name, String status,
                        String scanner, LocalDateTime lastScannedAt) {
}
