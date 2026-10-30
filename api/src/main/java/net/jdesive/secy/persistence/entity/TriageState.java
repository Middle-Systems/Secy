package net.jdesive.secy.persistence.entity;

/**
 * What a <b>person</b> decided about an actionable item — orthogonal to {@link AlertLifecycleState},
 * which records what the <em>scanner</em> observed. See that enum's Javadoc for why the two are
 * separate columns rather than one shared state machine: an operator can acknowledge an alert that
 * correlation later auto-resolves, and an auto-resolved alert keeps whatever triage was done to it.
 *
 * <p>No transition guard rules — every state may move to every other state. {@code TriageService}
 * appends a {@link TriageEvent} on every change so the history is never lost, but nothing in this
 * enum or its callers enforces an ordering between them.
 *
 * <p><b>M1j mapping</b> (ROADMAP.md — "Finding &amp; Action-item model"): kept alongside, mapped for
 * display, never written by the new machinery in either direction. A finding's derived
 * {@code RemediationStatus} maps {@code ACKNOWLEDGED} and an unexpired {@code SNOOZED} to
 * {@code IN_PROGRESS}, {@code FALSE_POSITIVE} to {@code NOT_AFFECTED} (labeled basis {@code TRIAGE},
 * not {@code VEX} — a person's dismissal, not VEX evidence) and the rest 1:1 — see
 * {@code net.jdesive.secy.service.finding.RemediationStatusDeriver.forFinding}.
 */
public enum TriageState {

    /** The default: nobody has looked at it yet. */
    OPEN,

    /** Someone has seen it and is on it, but it is neither resolved nor dismissed. */
    ACKNOWLEDGED,

    /** Deliberately hidden from the default list until {@code snoozedUntil} passes. */
    SNOOZED,

    /** Remediated. Kept, not deleted — the same "never delete" discipline as {@link AlertLifecycleState}. */
    RESOLVED,

    /** Triaged and judged not worth acting on. Kept for the same reason {@link #RESOLVED} is. */
    FALSE_POSITIVE

}
