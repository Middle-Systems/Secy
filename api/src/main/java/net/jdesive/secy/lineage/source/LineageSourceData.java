package net.jdesive.secy.lineage.source;

import java.util.List;

/** Everything {@code LineageSourceReader} read for one tenant, handed to {@code LineagePlanner}. */
public record LineageSourceData(List<ProductRow> products,
                                 List<SbomRow> sboms,
                                 List<ComponentRow> components,
                                 List<AssetRow> assets,
                                 List<AssetComponentRow> assetComponents,
                                 List<VulnerabilityRow> vulnerabilities,
                                 List<VulnerabilityAlertRow> alerts,
                                 List<CompromiseFindingRow> compromiseFindings) {
}
