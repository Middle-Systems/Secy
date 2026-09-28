package net.jdesive.secy.service.scoring;

import net.jdesive.secy.persistence.entity.VexStatus;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;

/**
 * The M1i-scoring view of an alert's M1f VEX resolution ({@link ScoreInput#VEX_STATUS}) — mirrors
 * {@link VexStatus} but adds two states {@code VexStatus} itself does not carry: {@link #NONE} (no
 * statement applies at all) and {@link #CONFLICT} (authors disagree in the winning precedence tier).
 *
 * <p>{@link #NOT_AFFECTED} and {@link #FIXED} zero the score ({@link ScoringWeights#DEFAULT}'s
 * {@code vexFactor}) while leaving the rest of the breakdown visible — the finding is not deleted,
 * just VEX-cleared. Every other state, including {@link #CONFLICT}, is neutral: a conflict is a flag
 * for review, not evidence either way.
 */
public enum VexScoringState {

    /** No VEX statement applies to this alert. */
    NONE,

    AFFECTED,

    UNDER_INVESTIGATION,

    NOT_AFFECTED,

    FIXED,

    /** Authors disagree in the winning precedence tier — nothing applies, flagged for review. */
    CONFLICT;

    /** Reads {@code alert}'s stored VEX snapshot; never throws. */
    public static VexScoringState of(VulnerabilityAlert alert) {
        if (alert.isVexConflict()) {
            return CONFLICT;
        }
        VexStatus status = alert.getVexStatus();
        if (status == null) {
            return NONE;
        }
        return switch (status) {
            case AFFECTED -> AFFECTED;
            case UNDER_INVESTIGATION -> UNDER_INVESTIGATION;
            case NOT_AFFECTED -> NOT_AFFECTED;
            case FIXED -> FIXED;
        };
    }

}
