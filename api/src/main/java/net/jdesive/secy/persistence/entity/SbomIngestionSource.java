package net.jdesive.secy.persistence.entity;

/**
 * The channel an {@link SBOM} arrived through (M1c, ROADMAP.md — "Canonical component identity").
 * Set once at ingestion by whichever entry point in {@code SBOMService} created the placeholder row;
 * {@code null} on any row that predates M1c.
 */
public enum SbomIngestionSource {

    /** {@code POST /sbom/{productId}/sboms} — a named product, chosen by the uploader. */
    MANUAL_UPLOAD,

    /** {@code POST /sbom} — M1a's tag-driven upload, resolved to a product via {@code tag=key=value} params. */
    TAGGED_UPLOAD,

    /** Phase 6b's GitHub connector sync — see {@code GitHubSyncService}. */
    GITHUB_CONNECTOR
}
