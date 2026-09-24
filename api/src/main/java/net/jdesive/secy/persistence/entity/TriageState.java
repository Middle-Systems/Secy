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
