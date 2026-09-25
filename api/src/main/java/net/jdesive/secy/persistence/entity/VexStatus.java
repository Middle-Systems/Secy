package net.jdesive.secy.persistence.entity;

/**
 * The four OpenVEX-shaped statuses M1f resolves every VEX statement onto, whatever format it came
 * from (see {@code net.jdesive.secy.service.vex.parser} for the per-format mapping tables).
 *
 * <p>Written only by {@code VexResolutionService} onto {@link VulnerabilityAlert#getVexStatus()} —
 * never by {@code EnrichmentService}, and never influences {@code actionable}/{@code triageState}.
 */
public enum VexStatus {

    /** The product is not affected by the vulnerability. */
    NOT_AFFECTED,

    /** The product is affected by the vulnerability. */
    AFFECTED,

    /** The product was affected but the vulnerability has been fixed. */
    FIXED,

    /** Whether the product is affected is not yet known. */
    UNDER_INVESTIGATION

}
