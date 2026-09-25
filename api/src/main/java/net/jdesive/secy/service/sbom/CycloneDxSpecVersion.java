package net.jdesive.secy.service.sbom;

import java.util.Optional;

/**
 * CycloneDX {@code specVersion} parsing for the M1g CBOM version floor (ROADMAP.md — "M1g — CBOM
 * ingestion"): {@code cryptographic-asset}/{@code cryptoProperties} first appear in the CycloneDX
 * 1.6 standard, so extraction is skipped below that floor.
 *
 * <p>A parallel version check already exists in {@code net.jdesive.secy.service.vex.VexDocumentParser}
 * ({@code isAtLeast14}, floor 1.4 for VEX). This is a deliberately separate, unrelated check — don't
 * reuse or modify that one for M1g.
 */
public final class CycloneDxSpecVersion {

    private CycloneDxSpecVersion() {
    }

    /**
     * Parses a CycloneDX {@code specVersion} string into {@code [major, minor]}, or empty when the
     * value is null/blank, has fewer than two dot-separated parts, or either of the first two parts
     * is not an integer.
     */
    public static Optional<int[]> parse(String specVersion) {
        if (specVersion == null || specVersion.isBlank()) {
            return Optional.empty();
        }
        String[] parts = specVersion.trim().split("\\.");
        if (parts.length < 2) {
            return Optional.empty();
        }
        try {
            int major = Integer.parseInt(parts[0].trim());
            int minor = Integer.parseInt(parts[1].trim());
            return Optional.of(new int[]{major, minor});
        } catch (NumberFormatException e) {
            return Optional.empty();
        }
    }

    /**
     * Whether this CycloneDX {@code specVersion} is within the range CBOM extraction supports:
     * major version exactly 1, minor {@code >= 6}. A hypothetical 2.x is a different object model —
     * crypto extraction is skipped, but the SBOM itself still ingests exactly as today.
     */
    public static boolean supportsCryptoAssets(String specVersion) {
        return parse(specVersion).map(p -> p[0] == 1 && p[1] >= 6).orElse(false);
    }

}
