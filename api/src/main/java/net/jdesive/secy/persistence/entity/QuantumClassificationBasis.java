package net.jdesive.secy.persistence.entity;

/**
 * What evidence {@link QuantumVulnerabilityStatus} was decided from (M1g), for a
 * {@code QuantumVulnerabilityFinding}'s {@code matchedIndicator} to explain.
 */
public enum QuantumClassificationBasis {
    /** A recognised algorithm OID (own or a referenced asset's). */
    OID,
    /** A recognised algorithm/protocol/cipher-suite name pattern. */
    NAME,
    /** A non-blank {@code algorithmProperties.curve}. */
    CURVE,
    /** {@code algorithmProperties.primitive} (symmetric/hash family, no identity match). */
    PRIMITIVE,
    /** The document's own {@code nistQuantumSecurityLevel}, used only to fill an otherwise-UNKNOWN gap. */
    DECLARED_NIST_LEVEL,
    /** Classification inherited from an {@code algorithmRef}/{@code signatureAlgorithmRef}/etc. target. */
    REFERENCED_ASSET,
    /** A CycloneDX {@code protocolProperties.cipherSuites[]} entry name. */
    CIPHER_SUITE
}
