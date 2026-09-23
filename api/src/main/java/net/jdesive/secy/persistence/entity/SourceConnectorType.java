package net.jdesive.secy.persistence.entity;

/**
 * Where a {@link SourceConnector} pulls inventory from.
 *
 * <p>{@code GITHUB} (Phase 6b's first slice) is SBOM ingest — a repo's own dependency-graph
 * document, through the same path a manual SPDX upload takes. {@code AWS} and {@code AZURE} are a
 * different shape: cloud resources enumerated into {@link Asset}s and run through Phase 4's
 * asset/Trivy-Grype pipeline ({@code AssetService#applyScan}) instead, with the cloud's own native
 * scanner (Amazon Inspector / Microsoft Defender for Cloud) standing in for Trivy/Grype so nothing
 * needs installing anywhere — genuinely agentless, per the locked scope decision.
 *
 * <p>{@code scope} means something different per type (see each value's Javadoc); the credential is
 * still one instance-wide set of env vars per provider, never a per-connector secret — the same
 * choice {@code GITHUB} made and for the same reason (a {@link SourceConnector} row says
 * <em>where</em> to look, never <em>with what credential</em>).
 */
public enum SourceConnectorType {

    /** GitHub org or user repos, synced via {@code GET /repos/{owner}/{repo}/dependency-graph/sbom}. */
    GITHUB,

    /**
     * One AWS region (that is what {@code scope} holds — e.g. {@code us-east-1}). Enumerates EC2
     * instances, ECR repositories/images and Lambda functions into {@link Asset}s, and reads
     * Amazon Inspector v2's own findings for them — Secy never scans an image itself.
     */
    AWS,

    /**
     * One Azure subscription (that is what {@code scope} holds — the subscription id). Enumerates
     * VMs and ACR repositories into {@link Asset}s, and reads Microsoft Defender for Cloud's own
     * vulnerability assessments for them.
     */
    AZURE

}
