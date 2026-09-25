package net.jdesive.secy.model.cbom;

/**
 * The CycloneDX {@code component.type} value for a cryptographic asset (M1g). Used by the normalizer
 * (to decide whether to extract {@code cryptoProperties}) and by correlation/compromise
 * detection/lifecycle drift (to exclude crypto components from package-oriented matching — see
 * ROADMAP.md's M1g note on the false-positive hazard).
 */
public final class CryptoAssets {

    public static final String COMPONENT_TYPE = "cryptographic-asset";

    private CryptoAssets() {
    }

    /** Trimmed, case-insensitive equality against {@link #COMPONENT_TYPE}. */
    public static boolean isCryptoAsset(String type) {
        return type != null && COMPONENT_TYPE.equalsIgnoreCase(type.trim());
    }

}
