package net.jdesive.secy.model.asset;

import net.jdesive.secy.model.actionable.ActionableItemResponse;
import net.jdesive.secy.persistence.entity.Asset;
import net.jdesive.secy.persistence.entity.AssetType;
import org.springframework.data.domain.Page;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

/**
 * {@code GET /assets/{id}} — the asset, plus its actionable items.
 *
 * <p>{@code actionableItems} is a plain page of {@link ActionableItemResponse}: the same rows, the
 * same sort and the same DTO the Actionable Items screen renders, obtained through the ordinary
 * {@code assetId} filter. An asset drill-down is a filtered view of the one list, not a second one.
 *
 * @param declaredCpes CPEs the operator declared for this asset, for the OS/firmware case no package
 *                     manager enumerates. Each is correlated as a PURL-less component through the CPE
 *                     fallback.
 */
public record AssetDetailResponse(
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
        List<String> declaredCpes,
        Page<ActionableItemResponse> actionableItems) {

    public static AssetDetailResponse of(Asset asset, long componentCount,
                                         Page<ActionableItemResponse> actionableItems) {
        return new AssetDetailResponse(
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
                List.copyOf(asset.getDeclaredCpes()),
                actionableItems);
    }

}
