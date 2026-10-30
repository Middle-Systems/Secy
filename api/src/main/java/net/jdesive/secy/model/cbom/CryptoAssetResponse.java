package net.jdesive.secy.model.cbom;

import net.jdesive.secy.persistence.entity.CryptoAssetType;
import net.jdesive.secy.persistence.entity.QuantumClassificationBasis;
import net.jdesive.secy.persistence.entity.QuantumVulnerabilityStatus;
import net.jdesive.secy.persistence.entity.QuantumVulnerableFamily;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.SBOMComponent;
import net.jdesive.secy.persistence.entity.SBOMComponentCryptoAsset;
import net.jdesive.secy.persistence.entity.SbomLifecycleStage;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

/**
 * One CycloneDX 1.6 crypto asset inventory row, for {@code GET /cbom/assets} (M1g). Never includes
 * the raw {@code cryptoProperties} JSON — see {@link CryptoAssetDetailResponse} for that.
 */
public record CryptoAssetResponse(
        UUID id,
        UUID componentId,
        UUID sbomId,
        UUID productId,
        SbomLifecycleStage lifecycleStage,
        String componentName,
        String bomRef,
        CryptoAssetType assetType,
        String declaredAssetType,
        String oid,
        String cryptoIdentityKey,
        String primitive,
        String parameterSetIdentifier,
        String curve,
        String executionEnvironment,
        String implementationPlatform,
        List<String> certificationLevels,
        String algorithmMode,
        String padding,
        List<String> cryptoFunctions,
        Integer classicalSecurityLevel,
        Integer nistQuantumSecurityLevel,
        String subjectName,
        String issuerName,
        LocalDateTime notValidBefore,
        LocalDateTime notValidAfter,
        String signatureAlgorithmRef,
        String subjectPublicKeyRef,
        String certificateFormat,
        String certificateExtension,
        String materialType,
        String materialId,
        String materialState,
        String algorithmRef,
        LocalDateTime materialCreationDate,
        LocalDateTime materialActivationDate,
        LocalDateTime materialUpdateDate,
        LocalDateTime materialExpirationDate,
        Integer materialSize,
        String materialFormat,
        String securedByMechanism,
        String securedByAlgorithmRef,
        String protocolType,
        String protocolVersion,
        List<String> cipherSuites,
        List<String> cryptoRefs,
        QuantumVulnerabilityStatus quantumStatus,
        QuantumVulnerableFamily quantumFamily,
        QuantumClassificationBasis quantumBasis,
        String quantumIndicator) {

    public static CryptoAssetResponse from(SBOMComponentCryptoAsset entity) {
        SBOMComponent component = entity.getComponent();
        SBOM sbom = component == null ? null : component.getSbom();
        return new CryptoAssetResponse(
                entity.getId(),
                component == null ? null : component.getId(),
                sbom == null ? null : sbom.getId(),
                sbom == null || sbom.getProduct() == null ? null : sbom.getProduct().getId(),
                sbom == null ? null : sbom.getLifecycleStage(),
                component == null ? null : component.getName(),
                component == null ? null : component.getBomRef(),
                entity.getAssetType(),
                entity.getDeclaredAssetType(),
                entity.getOid(),
                entity.getCryptoIdentityKey(),
                entity.getPrimitive(),
                entity.getParameterSetIdentifier(),
                entity.getCurve(),
                entity.getExecutionEnvironment(),
                entity.getImplementationPlatform(),
                split(entity.getCertificationLevels()),
                entity.getAlgorithmMode(),
                entity.getPadding(),
                split(entity.getCryptoFunctions()),
                entity.getClassicalSecurityLevel(),
                entity.getNistQuantumSecurityLevel(),
                entity.getSubjectName(),
                entity.getIssuerName(),
                entity.getNotValidBefore(),
                entity.getNotValidAfter(),
                entity.getSignatureAlgorithmRef(),
                entity.getSubjectPublicKeyRef(),
                entity.getCertificateFormat(),
                entity.getCertificateExtension(),
                entity.getMaterialType(),
                entity.getMaterialId(),
                entity.getMaterialState(),
                entity.getAlgorithmRef(),
                entity.getMaterialCreationDate(),
                entity.getMaterialActivationDate(),
                entity.getMaterialUpdateDate(),
                entity.getMaterialExpirationDate(),
                entity.getMaterialSize(),
                entity.getMaterialFormat(),
                entity.getSecuredByMechanism(),
                entity.getSecuredByAlgorithmRef(),
                entity.getProtocolType(),
                entity.getProtocolVersion(),
                split(entity.getCipherSuites()),
                split(entity.getCryptoRefs()),
                entity.getQuantumStatus(),
                entity.getQuantumFamily(),
                entity.getQuantumBasis(),
                entity.getQuantumIndicator());
    }

    /** Reverses the {@code ", "}-joined storage form back into a list. Null in, null out. */
    static List<String> split(String joined) {
        if (joined == null || joined.isBlank()) {
            return null;
        }
        return Arrays.stream(joined.split(",\\s*")).map(String::trim).filter(s -> !s.isEmpty()).toList();
    }

}
