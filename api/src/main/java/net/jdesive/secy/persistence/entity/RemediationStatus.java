package net.jdesive.secy.persistence.entity;

/**
 * One status vocabulary for both a finding's derived status ({@code FindingResponse.status}) and an
 * {@link ActionItem}'s stored/effective status (M1j — ROADMAP.md's "Finding &amp; Action-item model").
 * See {@code net.jdesive.secy.service.finding.RemediationStatusDeriver} for exactly how each is
 * derived.
 *
 * <p><b>{@link #NOT_AFFECTED} is never persisted on {@link ActionItem#getStatus()}.</b> It is only
 * ever a derived value — for a finding, off a VEX {@code NOT_AFFECTED} snapshot or a
 * {@code FALSE_POSITIVE} triage call; for an action item, off every linked active finding being VEX
 * {@code NOT_AFFECTED}. {@code ActionItemService} rejects a client request to set it directly with a
 * 400 — see {@code ActionItemController}.
 */
public enum RemediationStatus {

    /** Nobody has acted on it, or it reopened. The default. */
    OPEN,

    /** Someone is actively working it. */
    IN_PROGRESS,

    /** Deliberately not fixing this, with an expiry and a justification — see {@link ActionItem}. */
    RISK_ACCEPTED,

    /**
     * Derived only — see the class Javadoc. Never stored on {@link ActionItem#getStatus()}; a
     * finding-level {@code NOT_AFFECTED} is VEX- or triage-derived, never a stored column either.
     */
    NOT_AFFECTED,

    /** Remediated. Kept, not deleted — the same "never delete" discipline as {@link AlertLifecycleState}. */
    RESOLVED

}
