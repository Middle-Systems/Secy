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
    SBOM_UPLOAD

}
