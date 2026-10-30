package net.jdesive.secy.persistence.entity;

/**
 * Why an {@link ActionItemEvent}'s {@code toStatus} differs from what was actually stored, recorded
 * at the moment someone acts on a derived transition — see
 * {@code net.jdesive.secy.service.finding.RemediationStatusDeriver.forItem} for the derivation rules
 * this records. Derived transitions are never otherwise materialized (same discipline as snooze
 * expiry on {@code TriageState}); this enum exists purely so the history entry that finally does get
 * written says <em>why</em> the "from" status wasn't the stored one.
 */
public enum StatusDerivation {

    /** A linked finding came back {@code ACTIVE} with a fresher {@code lastSeenAt} than the item's {@code resolvedAt}. */
    REOPENED_ON_REAPPEARANCE,

    /** {@code riskAcceptedUntil} is no longer in the future. */
    RISK_ACCEPTANCE_EXPIRED,

    /** Every linked active (non-VEX-FIXED) finding is a vulnerability with VEX status {@code NOT_AFFECTED}. */
    VEX_NOT_AFFECTED

}
