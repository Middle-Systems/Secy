package net.jdesive.secy.persistence.entity;

/**
 * Why an alert made it through the actionable funnel.
 *
 * <p>Set at alert-generation time (and refreshed by re-enrichment) alongside
 * {@code VulnerabilityAlert.actionable}; {@code null} when the alert is not actionable.
 */
public enum ActionableReason {

    /** The CVE is on the CISA KEV catalog. */
    KEV,

    /** EPSS probability is strictly above {@code secy.actionable.epss-threshold}. */
    EPSS_HIGH,

    /** Both of the above. */
    KEV_AND_EPSS_HIGH

}
