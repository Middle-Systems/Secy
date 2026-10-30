package net.jdesive.secy.persistence.entity;

/** Lifecycle of one {@link VexDocument} through the {@code VEX_UPLOAD} job. */
public enum VexDocumentStatus {

    QUEUED,

    PROCESSING,

    COMPLETED,

    FAILED

}
