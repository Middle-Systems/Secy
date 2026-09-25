package net.jdesive.secy.model.cbom;

import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.CryptoAssetType;
import net.jdesive.secy.persistence.entity.QuantumClassificationBasis;
import net.jdesive.secy.persistence.entity.QuantumVulnerabilityFinding;
import net.jdesive.secy.persistence.entity.QuantumVulnerableFamily;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * One {@link QuantumVulnerabilityFinding}, in full — both a row of
 * {@code GET /cbom/quantum-findings} and the body of {@code GET /cbom/quantum-findings/{id}}. Same
 * "list and detail are the same shape" reasoning as {@code LifecycleDriftFindingResponse}.
 */
public record QuantumFindingResponse(
        UUID id,
        UUID productId,
        UUID scopeSbomId,
        String cryptoIdentityKey,
        CryptoAssetType assetType,
        QuantumVulnerableFamily algorithmFamily,
        QuantumClassificationBasis classificationBasis,
        String matchedIndicator,
        Integer declaredNistQuantumLevel,
        String componentName,
        String bomRef,
        UUID sbomId,
        UUID componentId,
        UUID cryptoAssetId,
        String summary,
        AlertLifecycleState lifecycleState,
        LocalDateTime createdAt,
        LocalDateTime lastSeenAt) {

    public static QuantumFindingResponse from(QuantumVulnerabilityFinding finding) {
        return new QuantumFindingResponse(
                finding.getId(),
                finding.getProductId(),
                finding.getScopeSbomId(),
                finding.getCryptoIdentityKey(),
                finding.getAssetType(),
                finding.getAlgorithmFamily(),
                finding.getClassificationBasis(),
                finding.getMatchedIndicator(),
                finding.getDeclaredNistQuantumLevel(),
                finding.getComponentName(),
                finding.getBomRef(),
                finding.getSbomId(),
                finding.getComponentId(),
                finding.getCryptoAssetId(),
                finding.getSummary(),
                finding.getLifecycleState(),
                finding.getCreatedAt(),
                finding.getLastSeenAt());
    }

}
