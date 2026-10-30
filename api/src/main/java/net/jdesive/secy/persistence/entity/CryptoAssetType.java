package net.jdesive.secy.persistence.entity;

/**
 * CycloneDX 1.6 {@code cryptoProperties.assetType} (M1g), lenient-mapped by
 * {@code CryptoPropertiesExtractor} — anything unrecognised or absent maps to {@link #UNKNOWN}
 * rather than failing the component.
 */
public enum CryptoAssetType {
    ALGORITHM,
    CERTIFICATE,
    PROTOCOL,
    RELATED_CRYPTO_MATERIAL,
    UNKNOWN
}
