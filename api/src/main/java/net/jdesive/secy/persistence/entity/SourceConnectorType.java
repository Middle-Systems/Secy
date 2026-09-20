package net.jdesive.secy.persistence.entity;

/**
 * Where a {@link SourceConnector} pulls inventory from.
 *
 * <p>Deliberately one value for this pass (Phase 6b, ROADMAP.md): GitHub only, agentless discovery
 * of a repo's dependency-graph SBOM. {@code AWS} and {@code AZURE} are the roadmap's named next
 * slice — cloud resources (EC2/ECR/Lambda, Azure VMs/ACR) enumerated and run through the Phase 4
 * asset/Trivy-Grype pipeline rather than SBOM ingest, which is a different enough shape that adding
 * them here now would be guessing at an API this pass does not need. Not built in this pass.
 */
public enum SourceConnectorType {

    /** GitHub org or user repos, synced via {@code GET /repos/{owner}/{repo}/dependency-graph/sbom}. */
    GITHUB

}
