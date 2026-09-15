package net.jdesive.secy.persistence.entity;

/** The feed an {@link Job} pulls. One background job per value may be active at a time. */
public enum JobType {

    /** NIST National Vulnerability Database CVE records. */
    NVD,

    /** FIRST Exploit Prediction Scoring System scores. */
    EPSS,

    /** CISA Known Exploited Vulnerabilities catalog. */
    KEV,

    /** Merged public exploit index — Nuclei templates, Metasploit modules, PoC-in-GitHub. */
    EXPLOIT,

    /** OSV per-ecosystem advisory mirror. */
    OSV,

    /** CVE List v5.1 + CISA-ADP Vulnrichment bulk snapshot. */
    CVE_LIST,

    /**
     * One uploaded SBOM document (CycloneDX or SPDX) being parsed, persisted and scanned (Phase 3).
     *
     * <p>Unlike every other value here, this is not a singleton feed pull: each upload is its own
     * unit of work with its own payload (which {@code sbom} row to finish ingesting), so more than
     * one may be {@code QUEUED}/{@code RUNNING} at once — one per concurrent upload. Enqueued via
     * {@code JobService.create()}, not {@code enqueue()}; see that method's Javadoc and migration
     * {@code 008b}, which narrows {@code uq_ingestion_job_active_type} to exclude this type.
     */
    SBOM_UPLOAD,

    /**
     * One uploaded infrastructure scan (Trivy or Grype) being parsed, persisted and correlated
     * (Phase 4).
     *
     * <p>Per-invocation like {@link #SBOM_UPLOAD} and for the same reason — each scan is its own unit
     * of work with its own payload (which {@code asset} row to finish ingesting) — so it is enqueued
     * via {@code JobService.create()} and excluded from {@code uq_ingestion_job_active_type} by
     * migration {@code 009}.
     */
    ASSET_SCAN,

    /**
     * One uploaded CIS/Docker compliance report being persisted and correlated (Phase 5).
     *
     * <p>Per-invocation like {@link #SBOM_UPLOAD} and {@link #ASSET_SCAN} — each report is its own
     * unit of work with its own payload (which {@code docker_compliance_report} row to finish) — so
     * it is enqueued via {@code JobService.create()} and excluded from
     * {@code uq_ingestion_job_active_type} by migration {@code 010}.
     *
     * <p>Covers both the upload and {@code POST /compliance/reports/{id}/scan}: a re-scan is the same
     * job doing the same correlation, just replaying the report's persisted findings instead of a raw
     * document.
     */
    COMPLIANCE_SCAN

}
