package net.jdesive.secy.persistence.entity;

/**
 * Why an item made it through the actionable funnel.
 *
 * <p>The first three are set at alert-generation time (and refreshed by re-enrichment) alongside
 * {@code VulnerabilityAlert.actionable}; {@code null} when the alert is not actionable.
 *
 * <p>{@link #COMPROMISE} is the odd one out and deliberately so — see its own note.
 */
public enum ActionableReason {

    /** The CVE is on the CISA KEV catalog. */
    KEV,

    /** EPSS probability is strictly above {@code secy.actionable.epss-threshold}. */
    EPSS_HIGH,

    /** Both of the above. */
    KEV_AND_EPSS_HIGH,

    /**
     * Phase 6's third promotion path: the item is a {@link CompromiseFinding} — something known-bad
     * is being shipped. There is no CVE, no EPSS score and no KEV entry to weigh, so none of the
     * limbs above can fire; the existence of the finding <em>is</em> the promotion.
     *
     * <p><b>Never stored on {@code vulnerability_alert.actionable_reason}.</b> Unlike its three
     * siblings this value is derived at response time by {@code ActionableService} when it maps a
     * {@code compromise_finding} row into the {@code GET /actionable} union, and it is what
     * {@code GET /actionable?reason=COMPROMISE} selects on. A {@code VulnerabilityAlert} can never
     * carry it: an alert always has a CVE behind it, and {@code EnrichmentService} only ever writes
     * the other three.
     */
    COMPROMISE

}
