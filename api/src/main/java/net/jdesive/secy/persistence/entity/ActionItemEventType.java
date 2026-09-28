package net.jdesive.secy.persistence.entity;

/**
 * What kind of {@link ActionItemEvent} row this is — the M1j analogue of {@code TriageEvent}'s
 * implicit "state change, comment, or both" shape, made explicit because an action item's history
 * covers more than status alone (assignment, finding attach/detach, edits).
 */
public enum ActionItemEventType {

    /** The item was created, with its initial findings attached in the same operation. */
    CREATED,

    /** {@link ActionItem#getStatus()} moved, whether requested directly or observed as a derived transition. */
    STATUS_CHANGED,

    /** An assignee was set (including changed from one person to another). */
    ASSIGNED,

    /** The assignee was cleared via {@code unassign: true}. */
    UNASSIGNED,

    /** A finding was linked via {@code POST /action-items/{id}/findings} or item creation. */
    FINDING_ATTACHED,

    /** A finding was unlinked via {@code DELETE /action-items/{id}/findings/{type}/{findingId}}. */
    FINDING_DETACHED,

    /** A free-text comment with no other change. */
    COMMENTED,

    /** Title/description edited. */
    EDITED

}
