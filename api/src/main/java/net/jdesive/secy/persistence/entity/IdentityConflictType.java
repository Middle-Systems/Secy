package net.jdesive.secy.persistence.entity;

/**
 * What kind of disagreement a {@code sbom_component_identity_conflict} row records (M1c,
 * ROADMAP.md — "Canonical component identity"). See {@code ComponentIdentityAssessor} for the
 * detection rules and {@code ComponentIdentityService} for the cross-instance hash-collision pass.
 */
public enum IdentityConflictType {

    /** A declared CPE's {@code product} (and, unless {@code vendor} is {@code ANY}, {@code vendor}) shares no name token with the primary identity. */
    CPE_NAME_MISMATCH,

    /** A declared CPE names a concrete version that disagrees with the component's effective version. */
    CPE_VERSION_MISMATCH,

    /** A CycloneDX {@code swid.name} shares no name token with the primary identity. */
    SWID_NAME_MISMATCH,

    /** A CycloneDX {@code swid.version} disagrees with the component's effective version. */
    SWID_VERSION_MISMATCH,

    /** Two declared digests share a canonical algorithm but differ in value — one artifact, two digests, impossible. */
    HASH_ALGORITHM_DISAGREEMENT,

    /** The same strong content digest was declared on components whose {@code identityKey}s differ, tenant-wide. */
    HASH_IDENTITY_COLLISION
}
