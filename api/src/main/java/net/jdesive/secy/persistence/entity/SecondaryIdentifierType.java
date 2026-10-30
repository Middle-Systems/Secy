package net.jdesive.secy.persistence.entity;

/**
 * A secondary identifier of an {@code sbom_component} instance — one alongside {@code identityKey},
 * never folded into it (M1c, ROADMAP.md — "Canonical component identity").
 *
 * <p>Only {@link #CPE} and {@link #SWID} are ever written to {@code sbom_component_identifier};
 * {@link #HASH} exists so a {@code sbom_component_identity_conflict} row or the identity API can
 * name a content digest as the offending identifier without a separate small enum, since hashes
 * live in {@code sbom_component_hash} and are never duplicated into the identifier table (see
 * {@code ComponentIdentityAssessor} and {@code ComponentIdentityService}).
 */
public enum SecondaryIdentifierType {
    CPE,
    SWID,
    HASH
}
