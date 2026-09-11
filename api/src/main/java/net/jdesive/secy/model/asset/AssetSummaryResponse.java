package net.jdesive.secy.model.asset;

import net.jdesive.secy.persistence.entity.Asset;
import net.jdesive.secy.persistence.entity.AssetType;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * One row of {@code GET /assets}.
 *
 * <p>Mapped explicitly off the entity rather than serialized from it, for the reason
 * {@code ActionableItemResponse} documents: {@code Asset}'s product and component relations are lazy,
 * and a list endpoint is exactly where an accidental proxy turns one request into a page of queries.
 *
 * @param componentCount  packages the most recent scan reported. Components kept as evidence of
 *                        something since removed from the asset are excluded — this is the current
 *                        inventory, not the historical one.
 * @param actionableCount alerts on this asset that cleared the funnel and are still {@code ACTIVE} —
 *                        the same predicate {@code GET /actionable} uses, so the badge and the
 *                        drill-down can never disagree.
 */
public record AssetSummaryResponse(
        UUID id,
        AssetType type,
        String name,
        UUID productId,
        String productName,
        String status,
        String scanner,
        LocalDateTime lastScannedAt,
        LocalDateTime createdAt,
        long componentCount,
        long actionableCount) {

    public static AssetSummaryResponse of(Asset asset, long componentCount, long actionableCount) {
        return new AssetSummaryResponse(
                asset.getId(),
                asset.getType(),
                asset.getName(),
                asset.getProduct() == null ? null : asset.getProduct().getId(),
                asset.getProduct() == null ? null : asset.getProduct().getName(),
                asset.getStatus(),
                asset.getScanner(),
                asset.getLastScannedAt(),
                asset.getCreatedAt(),
                componentCount,
                actionableCount);
    }

}
