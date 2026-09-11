package net.jdesive.secy.persistence.entity;

/** Where an {@link AssetComponent} row came from. Provenance only; it does not affect matching. */
public enum AssetComponentSource {

    /** Reported by {@code trivy image -f json}. */
    TRIVY,

    /** Reported by {@code grype -o json}. */
    GRYPE,

    /**
     * Not observed by a scanner at all — a CPE the operator declared for the asset, for the
     * OS/firmware/appliance case where no package manager exists to enumerate. Carries no PURL, so it
     * correlates through the CPE fallback path by construction.
     */
    DECLARED_CPE

}
