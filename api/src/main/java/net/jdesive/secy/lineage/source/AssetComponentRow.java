package net.jdesive.secy.lineage.source;

import net.jdesive.secy.persistence.entity.AssetComponentSource;

import java.util.UUID;

/**
 * One present-in-last-scan {@code asset_component} row, as read for lineage planning. The reader
 * excludes rows where {@code presentInLastScan = false} (see {@code LineageSourceReader}).
 */
public record AssetComponentRow(UUID id, UUID assetId, String name, String version, String purl,
                                 String identityKey, String ecosystem, AssetComponentSource source) {
}
