package net.jdesive.secy.model.asset;

import java.util.UUID;

/**
 * What {@code DELETE /assets/{id}} removed.
 *
 * <p>Returned with {@code 200} rather than answering a bare {@code 204}, because the delete cascades:
 * an operator who removes an asset should be told, in the same response, how many alerts went with
 * it. See {@code AssetService.delete} for why the cascade is a delete and not an auto-resolve.
 */
public record AssetDeletionSummary(UUID id, String name, int componentsRemoved, int alertsRemoved) {
}
