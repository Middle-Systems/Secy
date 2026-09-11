package net.jdesive.secy.persistence.entity;

/**
 * A CVE record's lifecycle state, as the CVE List v5.1 record and the CISA-ADP Vulnrichment
 * container report it.
 *
 * <p>Only {@link #PUBLISHED} records can clear the actionable funnel. A withdrawn or contested CVE
 * is still stored and still browsable — an operator who searched for it deserves to find it and see
 * why it is not on their list — but {@code EnrichmentService} refuses to promote it however high its
 * EPSS is and however firmly it sits on KEV.
 *
 * <p>Rows NVD ingested carry {@link #PUBLISHED}: NVD only publishes records the CVE Program has
 * published, and the migration backfills existing rows accordingly. The CVE-List-v5 feed is what
 * ever moves a row off that default.
 */
public enum CveStatus {

    /** The normal case: a live CVE record. */
    PUBLISHED,

    /**
     * The CNA withdrew the record — a duplicate, a non-issue, or an assignment made in error.
     * There is nothing to fix, so it must never reach the actionable list.
     */
    REJECTED,

    /**
     * The vendor contests that the report describes a vulnerability. The record stands, but acting
     * on it is a judgement call, not an obligation — so it stays out of the funnel and is surfaced
     * with its flag in the CVE browser instead.
     */
    DISPUTED

}
