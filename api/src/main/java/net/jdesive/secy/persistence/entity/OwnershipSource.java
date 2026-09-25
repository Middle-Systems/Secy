package net.jdesive.secy.persistence.entity;

/**
 * How an {@link OwnershipLink} was asserted. Only {@link #MANUAL} is written in M1b — {@link #INFERRED}
 * is reserved for M2 (CODEOWNERS, GitHub team permissions) and M3 (cloud resource owner tags).
 */
public enum OwnershipSource {
    MANUAL,
    INFERRED
}
