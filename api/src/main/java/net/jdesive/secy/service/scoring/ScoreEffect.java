package net.jdesive.secy.service.scoring;

/** How a {@link ScoreInput} applies to the running score (M1i). Follows the CVSS shape: additive points first, then multipliers. */
public enum ScoreEffect {

    /** Added to the running score, then clamped to {@code [0, 100]}. */
    ADD,

    /** Multiplies the running score. Every multiplier weight is validated in {@code [0, 1]}, so no clamp is needed after. */
    MULTIPLY

}
