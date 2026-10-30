package net.jdesive.secy.persistence.entity;

/**
 * The five OpenVEX justification values, which CycloneDX's {@code analysis.justification} and CSAF's
 * {@code flags[].label} both map onto 1:1 (see {@code net.jdesive.secy.service.vex.parser}). Only
 * meaningful alongside {@link VexStatus#NOT_AFFECTED}.
 */
public enum VexJustification {

    /** The vulnerable component is not included in the artifact. */
    COMPONENT_NOT_PRESENT,

    /** The vulnerable code is not included in the artifact. */
    VULNERABLE_CODE_NOT_PRESENT,

    /** The vulnerable code is included, but not in an execute path. */
    VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,

    /** The vulnerable code is included and in an execute path, but requires configuration only an
     *  adversary controls to be exploitable. */
    VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY,

    /** Inline mitigations already exist that prevent exploitation. */
    INLINE_MITIGATIONS_ALREADY_EXIST

}
