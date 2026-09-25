package net.jdesive.secy.persistence.entity;

/**
 * Which Shor-broken algorithm family a {@link QuantumVulnerabilityStatus#VULNERABLE} crypto asset
 * belongs to (M1g). {@code ElGamal} classifies as {@link #FINITE_FIELD_DH} — it shares the same
 * discrete-logarithm hardness assumption as classic Diffie-Hellman. {@link #OTHER_ASYMMETRIC} is used
 * only for the declared-NIST-quantum-level fallback rule, when no OID/name/curve identified a more
 * specific family.
 */
public enum QuantumVulnerableFamily {
    RSA,
    ECC,
    DSA,
    FINITE_FIELD_DH,
    OTHER_ASYMMETRIC
}
