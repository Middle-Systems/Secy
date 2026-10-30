package net.jdesive.secy.model.cbom;

import net.jdesive.secy.persistence.entity.CryptoAssetType;
import net.jdesive.secy.persistence.entity.QuantumVulnerabilityStatus;

import java.util.UUID;

/**
 * The {@code GET /cbom/assets} query string, parsed. Every field is optional.
 *
 * @param productId      only assets on this product's SBOM(s)
 * @param sbomId         only assets on this SBOM
 * @param assetType      exact {@link CryptoAssetType}
 * @param quantumStatus  exact {@link QuantumVulnerabilityStatus}
 * @param includeInactive false (default) restricts to rows on an {@code sbom.active = true} SBOM
 */
public record CryptoAssetFilter(UUID productId, UUID sbomId, CryptoAssetType assetType,
                                QuantumVulnerabilityStatus quantumStatus, boolean includeInactive) {
}
