package net.jdesive.secy.service.scoring;

import net.jdesive.secy.persistence.entity.ActionableReason;
import net.jdesive.secy.persistence.entity.DependencyDepth;
import net.jdesive.secy.persistence.entity.ExploitMaturity;
import net.jdesive.secy.persistence.entity.FixState;
import net.jdesive.secy.persistence.entity.SBOMComponent;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;

/**
 * {@link RiskScorer}'s input, read null-safely off one {@link VulnerabilityAlert} and its
 * association chain (M1i, ROADMAP.md — "Scoring engine rework").
 */
public record RiskScoreInputs(
        Double cvssScore,
        String baseSeverity,
        boolean kevListed,
        Double epssScore,
        ExploitMaturity exploitMaturity,
        LifecyclePresence lifecycle,
        VexScoringState vex,
        DependencyDepth depth,
        FixState fixState) {

    /**
     * Reads {@code alert}'s own snapshots plus {@code alert.component.sbom.lifecycleStage} —
     * everything else on this record's associations, never anything from {@code Vulnerability}
     * itself except {@code baseSeverity}.
     */
    public static RiskScoreInputs from(VulnerabilityAlert alert) {
        return new RiskScoreInputs(
                alert.getCvssScore(),
                alert.getVulnerability() == null ? null : alert.getVulnerability().getBaseSeverity(),
                isKevListed(alert),
                alert.getEpssScore(),
                alert.getExploitMaturity(),
                LifecyclePresence.of(alert),
                VexScoringState.of(alert),
                dependencyDepthOf(alert),
                alert.getFixState());
    }

    /**
     * M1l: the alert's SBOM component's ingest-time classification; asset/scanner alerts, pre-M1l
     * rows and directly-built components (no {@code component}, or a null {@code dependencyDepth}
     * column) are all {@link DependencyDepth#UNKNOWN}.
     */
    static DependencyDepth dependencyDepthOf(VulnerabilityAlert alert) {
        SBOMComponent c = alert.getComponent();
        return c == null || c.getDependencyDepth() == null ? DependencyDepth.UNKNOWN : c.getDependencyDepth();
    }

    /**
     * Whether {@code alert}'s CVE is KEV-listed — extracted from the expression
     * {@code ActionableService.toRow} computed inline before M1i, so both places agree by
     * construction rather than by two authors keeping two copies in sync.
     */
    public static boolean isKevListed(VulnerabilityAlert alert) {
        return alert.getKevDueDate() != null
                || alert.getActionableReason() == ActionableReason.KEV
                || alert.getActionableReason() == ActionableReason.KEV_AND_EPSS_HIGH;
    }

}
