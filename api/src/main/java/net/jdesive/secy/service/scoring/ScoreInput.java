package net.jdesive.secy.service.scoring;

/**
 * The eight inputs {@link RiskScorer} folds into a risk score (M1i, ROADMAP.md — "Scoring engine
 * rework"), each with its own row in {@link ScoringWeights}.
 *
 * <p><b>Declaration order is application order, and application order is breakdown order.</b>
 * {@link RiskScorer#score} walks {@link #values()} in this exact sequence — additive severity and
 * exploitation points first, then the contextual multipliers — and {@link RiskScoreResult#factors()}
 * (via {@code net.jdesive.secy.model.scoring.RiskScoreResult}) reports them in the same order, so a
 * client can render the breakdown top-to-bottom without re-sorting.
 */
public enum ScoreInput {

    /** CVSS base score (or a severity-band fallback), additive. */
    CVSS_BASE,

    /** CISA KEV listing, additive. */
    KEV,

    /** FIRST EPSS probability, additive. */
    EPSS,

    /** Public exploit maturity, additive — suppressed to zero when {@link #KEV} already fired. */
    EXPLOIT_MATURITY,

    /** Where in the SDLC this finding was observed, multiplicative. */
    LIFECYCLE_PRESENCE,

    /** VEX resolution status, multiplicative. */
    VEX_STATUS,

    /** Direct vs. transitive dependency (M1l placeholder), multiplicative. */
    DEPENDENCY_DEPTH,

    /** Whether a fix is available, multiplicative. */
    FIX_AVAILABILITY

}
