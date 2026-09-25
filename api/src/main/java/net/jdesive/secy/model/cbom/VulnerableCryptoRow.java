package net.jdesive.secy.model.cbom;

import net.jdesive.secy.persistence.entity.CryptoAssetType;
import net.jdesive.secy.persistence.entity.QuantumClassificationBasis;
import net.jdesive.secy.persistence.entity.QuantumVulnerableFamily;

import java.util.UUID;

/**
 * One {@code sbom_component_crypto_asset} row classified {@code VULNERABLE}, projected for
 * {@code QuantumFindingService.reconcileForSbom} (M1g) — the crypto-finding twin of
 * {@code net.jdesive.secy.model.lifecycle.StageComponent}.
 *
 * @param cryptoAssetId the {@code sbom_component_crypto_asset} row id
 * @param componentId   the owning {@code sbom_component} row id
 * @param sbomId        the owning SBOM id
 * @param cryptoIdentityKey the crypto-specific identity (see {@link CryptoAssetIdentity})
 * @param assetType     ALGORITHM / CERTIFICATE / PROTOCOL / RELATED_CRYPTO_MATERIAL / UNKNOWN
 * @param componentName the owning component's declared name
 * @param bomRef        the owning component's declared {@code bom-ref}
 * @param family        which Shor-broken family
 * @param basis         what evidence decided it
 * @param indicator     the matched OID/name/curve/ref/cipher-suite token
 * @param declaredNistQuantumLevel the document's own declared level, when present, for the summary's contradiction note
 * @param primitive     the deciding algorithm's own primitive, for the migration-hint text
 */
public record VulnerableCryptoRow(UUID cryptoAssetId, UUID componentId, UUID sbomId, String cryptoIdentityKey,
                                  CryptoAssetType assetType, String componentName, String bomRef,
                                  QuantumVulnerableFamily family, QuantumClassificationBasis basis,
                                  String indicator, Integer declaredNistQuantumLevel, String primitive) {
}
