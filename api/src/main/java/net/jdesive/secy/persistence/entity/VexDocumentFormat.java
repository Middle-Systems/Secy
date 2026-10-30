package net.jdesive.secy.persistence.entity;

/** Which document shape a {@link VexDocument} was parsed from. */
public enum VexDocumentFormat {

    OPENVEX,

    /** CSAF 2.0, and only the subset {@code net.jdesive.secy.service.vex.parser.CsafVexParser} implements. */
    CSAF,

    CYCLONEDX

}
