package net.jdesive.secy.model.cbom;

import net.jdesive.secy.persistence.entity.CryptoAssetType;

import java.util.Locale;

/**
 * The stable identity of a crypto asset for M1g's quantum-vulnerability finding reconciliation —
 * <b>not</b> {@code sbom_component.identity_key}. {@code ComponentIdentity.keyOf} is unchanged and
 * still computes normally for a crypto-typed {@code sbom_component} row; this is a separate,
 * crypto-specific key used only by {@code SBOMComponentCryptoAsset}/{@code QuantumVulnerabilityFinding}.
 *
 * <h2>Known collapse</h2>
 *
 * <p>Two crypto assets of the same type and name in one product's scope collapse onto one finding —
 * the most-downstream stage's row becomes the representative, mirroring {@code SbomCorrelationScope}'s
 * "most-downstream wins" rule.
 */
public final class CryptoAssetIdentity {

    public static final int MAX_LENGTH = 512;

    private CryptoAssetIdentity() {
    }

    /**
     * {@code cbom:<slug>:<lower(trim(name))>} when a name is present, else
     * {@code cbom:<slug>:oid:<oid>} when only an OID is present, else {@code null}.
     */
    public static String keyOf(CryptoAssetType type, String name, String oid) {
        String slug = slugOf(type);
        String trimmedName = name == null ? null : name.trim();
        if (trimmedName != null && !trimmedName.isEmpty()) {
            return truncate("cbom:" + slug + ":" + trimmedName.toLowerCase(Locale.ROOT));
        }
        String trimmedOid = oid == null ? null : oid.trim();
        if (trimmedOid != null && !trimmedOid.isEmpty()) {
            return truncate("cbom:" + slug + ":oid:" + trimmedOid);
        }
        return null;
    }

    private static String slugOf(CryptoAssetType type) {
        if (type == null) {
            return "unknown";
        }
        return switch (type) {
            case ALGORITHM -> "algorithm";
            case CERTIFICATE -> "certificate";
            case PROTOCOL -> "protocol";
            case RELATED_CRYPTO_MATERIAL -> "related-crypto-material";
            case UNKNOWN -> "unknown";
        };
    }

    private static String truncate(String key) {
        return key.length() <= MAX_LENGTH ? key : key.substring(0, MAX_LENGTH);
    }

}
