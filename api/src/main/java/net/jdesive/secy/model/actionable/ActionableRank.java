package net.jdesive.secy.model.actionable;

/**
 * {@code GET /actionable}'s {@code rankBy} — which secondary sort key {@code ActionableService}
 * applies to the vulnerability tier (M1i, ROADMAP.md — "Scoring engine rework").
 *
 * <p><b>{@link #EPSS} stays the default</b> — the pinned Phase-1 contract
 * ({@code rowsAreSortedByEpssDescendingWithMissingScoresLast}) — with the M1i risk score added only
 * as a tie-breaker ahead of {@code createdAt}. {@link #SCORE} is opt-in: it swaps the primary and
 * secondary keys, still falling through to {@code createdAt desc, id asc}. Neither mode touches the
 * compromise tier, which always sorts first by its own rules.
 */
public enum ActionableRank {

    /** {@code coalesce(epssScore,-1) desc, coalesce(riskScore,-1) desc, createdAt desc, id asc} — the default. */
    EPSS,

    /** {@code coalesce(riskScore,-1) desc, coalesce(epssScore,-1) desc, createdAt desc, id asc} — opt-in. */
    SCORE

}
