package net.jdesive.secy.persistence.entity;

/**
 * What kind of disagreement a {@link LifecycleDriftFinding} reports between an adjacent pair of
 * lifecycle-stage SBOMs (M1e). See {@code LifecycleDiffer} for exactly how each is computed.
 */
public enum LifecycleDriftKind {

    /** A component in the observed (downstream) SBOM that the baseline SBOM never declared. */
    UNEXPECTED_COMPONENT,

    /**
     * A component present in both, where the observed SBOM has at least one concrete version the
     * baseline SBOM never declared.
     */
    VERSION_MISMATCH
}
