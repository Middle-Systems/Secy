package net.jdesive.secy.model.actionable;

import net.jdesive.secy.persistence.entity.TriageState;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * One row of {@code GET /actionable/{id}/history} — a state transition, a comment, or both.
 *
 * @param id          the event id
 * @param fromState   the state before this event; null for a pure comment
 * @param toState     the state after this event; null for a pure comment
 * @param comment     the note recorded with this event, if any
 * @param changedById who made the change
 * @param changedByName that person's display name, falling back to their email
 * @param createdAt   when the event was recorded
 */
public record TriageEventResponse(
        UUID id,
        TriageState fromState,
        TriageState toState,
        String comment,
        UUID changedById,
        String changedByName,
        LocalDateTime createdAt) {
}
