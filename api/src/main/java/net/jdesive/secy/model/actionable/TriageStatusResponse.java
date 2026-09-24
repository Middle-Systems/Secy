package net.jdesive.secy.model.actionable;

import net.jdesive.secy.persistence.entity.TriageState;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * The triage state of one actionable item after {@code PATCH /actionable/{id}} applies a change.
 *
 * @param id            the item's id — a {@code VulnerabilityAlert} or {@code CompromiseFinding} id
 * @param itemType      which table {@link #id} is in
 * @param triageState   the state after this update
 * @param assigneeId    who is on it, or null
 * @param assigneeName  that assignee's display name, falling back to their email — or null
 * @param snoozedUntil  when it reappears, when {@link #triageState} is {@code SNOOZED}
 */
public record TriageStatusResponse(
        UUID id,
        ActionableItemType itemType,
        TriageState triageState,
        UUID assigneeId,
        String assigneeName,
        LocalDateTime snoozedUntil) {
}
