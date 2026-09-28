package net.jdesive.secy.model.actionitem;

import java.util.UUID;

/**
 * An action item's computed (never stored) risk-score rollup — the MAX over its linked
 * {@code VULNERABILITY} findings in {@code remaining} (active, not VEX not-affected/fixed), same
 * "max, explainable via topFindingId" rule as M1i's product/asset rollups. Compromise/drift/quantum/
 * quality links count in {@code findingCountsByType} but never contribute here — those types are
 * never scored (see M1i's/M1j's Javadoc on the three newer finding entities).
 */
public record ActionItemScore(
        Double riskScore,
        UUID topFindingId,
        long scoredVulnerabilityCount,
        long unscoredVulnerabilityCount) {
}
