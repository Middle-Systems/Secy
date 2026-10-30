package net.jdesive.secy.model.finding;

/**
 * Which rule produced a {@code FindingResponse.status} — see
 * {@code net.jdesive.secy.service.finding.RemediationStatusDeriver.forFinding} for the precedence
 * order these five values are tried in.
 */
public enum FindingStatusBasis {

    /** The finding's own {@code AlertLifecycleState} is {@code AUTO_RESOLVED}. */
    LIFECYCLE,

    /** A {@code VulnerabilityAlert}'s VEX snapshot ({@code NOT_AFFECTED}/{@code FIXED}). */
    VEX,

    /** The finding is linked to an {@code ActionItem}; its effective status won. */
    ACTION_ITEM,

    /** The finding's own {@code TriageState} (vulnerability/compromise only). */
    TRIAGE,

    /** Nothing else applied — an unlinked, active, untriaged finding. */
    DEFAULT

}
