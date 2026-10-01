package net.jdesive.secy.model.finding;

import net.jdesive.secy.persistence.entity.FixSource;

/**
 * "What would fix this finding" — M1k's additive per-finding guidance (ROADMAP.md, "Role-based
 * views" §5). Rides on {@code ResolvedFinding}/{@code FindingResponse}; never gates anything, never
 * stored. See {@code FindingFixAdvisor} for how each {@link FixKind} is produced.
 *
 * @param fixedVersions verbatim from {@code VulnerabilityAlert.fixedVersions} when {@link #kind} is
 *                      {@link FixKind#UPGRADE}; null otherwise
 * @param fixSource     verbatim from {@code VulnerabilityAlert.fixSource} when {@link #kind} is
 *                      {@link FixKind#UPGRADE}; null otherwise
 * @param guidance      human-readable text — data-derived for vulnerabilities, fixed templated text
 *                      for the other four finding types (see {@code FindingFixAdvisor})
 */
public record FindingFix(FixKind kind, String fixedVersions, FixSource fixSource, String guidance) {
}
