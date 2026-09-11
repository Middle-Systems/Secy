package net.jdesive.secy.model.grype;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * One Grype finding: a vulnerability and the artifact it was matched against.
 *
 * @param vulnerability        the advisory Grype matched
 * @param relatedVulnerabilities other ids for the same issue. This is where the CVE lives when
 *                             {@code vulnerability.id} is a GHSA — Grype indexes GitHub advisories
 *                             under their GHSA id and lists the CVE here.
 * @param artifact             the package the match is against
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GrypeMatch(GrypeVulnerability vulnerability,
                         List<GrypeVulnerability> relatedVulnerabilities,
                         GrypeArtifact artifact) {

    public GrypeMatch {
        relatedVulnerabilities = relatedVulnerabilities == null ? List.of() : List.copyOf(relatedVulnerabilities);
    }

}
