package net.jdesive.secy.model.actionable;

import net.jdesive.secy.persistence.entity.TriageState;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Body of {@code PATCH /actionable/{id}}. A partial update: a null field means "don't touch this",
 * not "clear it" — {@code TriageService.updateState} only writes the fields actually present.
 *
 * @param state        the new {@link TriageState}, or null to leave it unchanged
 * @param assigneeId   the new assignee, or null to leave the current assignee unchanged. There is
 *                      deliberately no way to unassign through this field alone — see
 *                      {@code TriageService} if that becomes a real need
 * @param snoozedUntil when a {@link TriageState#SNOOZED} item should reappear on the default list;
 *                     only meaningful alongside {@code state = SNOOZED}
 * @param comment      an optional note recorded alongside this change, whether or not the state moved
 */
public record TriagePatchRequest(
        TriageState state,
        UUID assigneeId,
        LocalDateTime snoozedUntil,
        String comment) {
}
