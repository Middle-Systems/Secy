package net.jdesive.secy.model.cbom;

import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.CryptoAssetType;
import net.jdesive.secy.persistence.entity.QuantumVulnerableFamily;

import java.util.UUID;

/**
 * The {@code GET /cbom/quantum-findings} query string, parsed. Every field is optional.
 *
 * @param productId      only findings for this product
 * @param assetType      exact {@link CryptoAssetType}
 * @param family         exact {@link QuantumVulnerableFamily}
 * @param lifecycleState defaults to {@code ACTIVE} when null
 */
public record QuantumFindingFilter(UUID productId, CryptoAssetType assetType, QuantumVulnerableFamily family,
                                   AlertLifecycleState lifecycleState) {

    public AlertLifecycleState effectiveLifecycleState() {
        return lifecycleState == null ? AlertLifecycleState.ACTIVE : lifecycleState;
    }

}
