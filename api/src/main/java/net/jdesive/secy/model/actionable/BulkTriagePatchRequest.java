package net.jdesive.secy.model.actionable;

import net.jdesive.secy.persistence.entity.TriageState;

import java.util.List;
import java.util.UUID;

/**
 * Body of {@code PATCH /actionable} (bulk, no path variable) — the same state/assignee update as
 * {@link TriagePatchRequest}, applied to every id in {@link #ids}. An id that resolves to neither
 * {@code VulnerabilityAlert} nor {@code CompromiseFinding} is silently skipped rather than failing the
 * whole batch — the same "one bad item does not fail the rest" philosophy
 * {@code GitHubSyncService} already applies per-repo.
 *
 * @param ids        the items to update, of either kind, mixed freely
 * @param state      the new {@link TriageState} for every item
 * @param assigneeId the new assignee for every item, or null to leave assignment unchanged
 */
public record BulkTriagePatchRequest(
        List<UUID> ids,
        TriageState state,
        UUID assigneeId) {
}
