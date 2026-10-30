package net.jdesive.secy.model.cbom;

import net.jdesive.secy.persistence.entity.CryptoAssetType;

import java.time.LocalDateTime;
import java.util.List;

/**
 * A CycloneDX 1.6 {@code cryptoProperties} subtree, normalized (M1g). Produced only by
 * {@code CryptoPropertiesExtractor}, which never throws — an unparseable/malformed shape degrades to
 * {@link #assetType} {@code UNKNOWN} with everything else null, never a parse failure for the whole
 * component.
 *
 * <p>{@code relatedCryptoMaterialProperties.value} (real key material) is <b>never</b> captured, in
 * either the typed {@link RelatedMaterial} or {@link #sanitizedJson}.
 *
 * @param assetType         mapped {@link CryptoAssetType}, lenient — unrecognised/absent → {@code UNKNOWN}
 * @param declaredAssetType the document's own {@code assetType} string, verbatim, whatever it mapped to
 * @param oid                {@code cryptoProperties.oid}
 * @param algorithm          present only when {@code assetType == ALGORITHM}-shaped data existed
 * @param certificate        present only when {@code certificateProperties} existed
 * @param relatedMaterial    present only when {@code relatedCryptoMaterialProperties} existed
 * @param protocol           present only when {@code protocolProperties} existed
 * @param sanitizedJson      a deep copy of {@code cryptoProperties} with {@code relatedCryptoMaterialProperties.value}
 *                           removed, serialized; null if it would exceed 16,384 characters or nothing was captured
 */
public record NormalizedCryptoAsset(CryptoAssetType assetType, String declaredAssetType, String oid,
                                    Algorithm algorithm, Certificate certificate,
                                    RelatedMaterial relatedMaterial, Protocol protocol,
                                    String sanitizedJson) {

    public record Algorithm(String primitive, String parameterSetIdentifier, String curve,
                            String executionEnvironment, String implementationPlatform,
                            List<String> certificationLevels, String mode, String padding,
                            List<String> cryptoFunctions, Integer classicalSecurityLevel,
                            Integer nistQuantumSecurityLevel) {
    }

    public record Certificate(String subjectName, String issuerName, LocalDateTime notValidBefore,
                              LocalDateTime notValidAfter, String signatureAlgorithmRef,
                              String subjectPublicKeyRef, String certificateFormat,
                              String certificateExtension) {
    }

    public record RelatedMaterial(String type, String id, String state, String algorithmRef,
                                  LocalDateTime creationDate, LocalDateTime activationDate,
                                  LocalDateTime updateDate, LocalDateTime expirationDate, Integer size,
                                  String format, String securedByMechanism, String securedByAlgorithmRef) {
    }

    public record Protocol(String type, String version, List<CipherSuite> cipherSuites,
                           List<String> cryptoRefs) {
    }

    public record CipherSuite(String name, List<String> algorithmRefs) {
    }

}
