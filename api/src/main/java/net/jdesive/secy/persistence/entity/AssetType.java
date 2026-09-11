package net.jdesive.secy.persistence.entity;

/** What kind of thing an {@link Asset} is. */
public enum AssetType {

    /** A container image, identified by {@code repository:tag} — the Phase 4 scan target. */
    CONTAINER_IMAGE,

    /** A machine: a VM, a bare-metal box, a node. Identified by hostname. */
    HOST,

    /** A running service or deployment that is neither of the above. */
    SERVICE

}
