package net.jdesive.secy.persistence.entity;

/**
 * Whether a re-scan still reproduces this alert.
 *
 * <p>Correlation never deletes an alert. When a component is upgraded past the affected range, or an
 * advisory narrows, or the SBOM stops shipping the package, the existing row is moved to
 * {@link #AUTO_RESOLVED} and kept — the history of "you were exposed and then you were not" is worth
 * more than the row it costs, and a deleted row silently loses whatever triage a human had done to
 * it. If a later scan reproduces the match, the same row goes back to {@link #ACTIVE}.
 *
 * <p><b>This is not the triage state machine.</b> Phase 7 owns
 * {@code OPEN → ACKNOWLEDGED → SNOOZED → RESOLVED | FALSE_POSITIVE}, which records what a
 * <em>person</em> decided. This enum records what the <em>scanner</em> observed, and the two are
 * orthogonal: an operator can acknowledge an alert that correlation later auto-resolves. Phase 7
 * should add its own column rather than extend this one.
 */
public enum AlertLifecycleState {

    /** The most recent correlation of the owning SBOM reproduced this match. */
    ACTIVE,

    /**
     * The most recent correlation did not reproduce this match. Kept, hidden from
     * {@code GET /actionable} by default, and revived automatically if the match returns.
     */
    AUTO_RESOLVED

}
