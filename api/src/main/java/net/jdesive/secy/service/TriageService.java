package net.jdesive.secy.service;

import lombok.RequiredArgsConstructor;
import net.jdesive.secy.model.actionable.ActionableItemType;
import net.jdesive.secy.model.actionable.TriageEventResponse;
import net.jdesive.secy.model.actionable.TriageStatusResponse;
import net.jdesive.secy.persistence.AppUserRepository;
import net.jdesive.secy.persistence.CompromiseFindingRepository;
import net.jdesive.secy.persistence.TriageEventRepository;
import net.jdesive.secy.persistence.VulnerabilityAlertRepository;
import net.jdesive.secy.persistence.entity.CompromiseFinding;
import net.jdesive.secy.persistence.entity.TriageEvent;
import net.jdesive.secy.persistence.entity.TriageState;
import net.jdesive.secy.persistence.entity.User;
import net.jdesive.secy.persistence.entity.VulnerabilityAlert;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * The Phase 7 triage state machine: what a <b>person</b> decided about an actionable item, appended
 * as history rather than overwritten — see {@code TriageState} and {@code AlertLifecycleState} for
 * why this is a column of its own rather than an extension of the scanner's lifecycle state.
 *
 * <h2>Resolving across the typed union</h2>
 *
 * <p>An actionable item's id is either a {@code VulnerabilityAlert} id or a {@code CompromiseFinding}
 * id, and the caller (a triage action off the {@code GET /actionable} list) does not necessarily know
 * which. Every public method here resolves against both tables via {@link #resolve(UUID)} — a plain
 * "try one, then the other" rather than a shared entity interface, because this codebase deliberately
 * has none (see {@code CompromiseFinding}'s class Javadoc): a {@code VulnerabilityAlert} and a
 * {@code CompromiseFinding} are two different kinds of thing that happen to both need triaging, not
 * one kind wearing two hats.
 *
 * <h2>No transition guard</h2>
 *
 * <p>Every {@link TriageState} may move to every other one — the roadmap specifies no state machine
 * beyond the enum itself. What is enforced is attribution and history: every change is recorded as a
 * new, immutable {@link TriageEvent} row, never an overwrite of the previous one.
 */
@Service
@RequiredArgsConstructor
public class TriageService {

    private final VulnerabilityAlertRepository alertRepository;

    private final CompromiseFindingRepository findingRepository;

    private final TriageEventRepository eventRepository;

    private final AppUserRepository userRepository;

    /**
     * Apply a partial update (null fields left untouched) and append one history event.
     *
     * @param id           a {@code VulnerabilityAlert} or {@code CompromiseFinding} id
     * @param newState     the new triage state, or null to leave it unchanged
     * @param assigneeId   the new assignee, or null to leave the current assignee unchanged
     * @param snoozedUntil the new snooze expiry, or null to leave it unchanged
     * @param comment      an optional note recorded alongside this change
     * @param actingUser   who is making the change — every event is attributed
     * @return the item's status after the update, or empty when {@code id} resolves to neither table
     */
    @Transactional
    public Optional<TriageStatusResponse> updateState(UUID id, TriageState newState, UUID assigneeId,
                                                        LocalDateTime snoozedUntil, String comment, User actingUser) {
        Optional<Target> target = resolve(id);
        if (target.isEmpty()) {
            return Optional.empty();
        }
        Target t = target.get();
        TriageState before = t.getTriageState();

        if (newState != null) {
            t.setTriageState(newState);
        }
        if (assigneeId != null) {
            userRepository.findById(assigneeId).ifPresent(t::setAssignee);
        }
        if (snoozedUntil != null) {
            t.setSnoozedUntil(snoozedUntil);
        }

        TriageState after = t.getTriageState();
        boolean stateChanged = newState != null && !before.equals(after);
        appendEvent(t, before, stateChanged ? after : null, comment, actingUser);
        t.save();

        return Optional.of(t.toStatusResponse());
    }

    /**
     * Append a comment with no state change. {@code triageState}/{@code assignee}/{@code snoozedUntil}
     * are left exactly as they were.
     */
    @Transactional
    public Optional<TriageEventResponse> addComment(UUID id, String comment, User actingUser) {
        Optional<Target> target = resolve(id);
        if (target.isEmpty()) {
            return Optional.empty();
        }
        Target t = target.get();
        TriageEvent event = appendEvent(t, null, null, comment, actingUser);
        return Optional.of(toEventResponse(event));
    }

    /**
     * The same per-item update as {@link #updateState}, applied to every id in {@code ids}. An id that
     * resolves to neither table is silently skipped — one bad id does not fail the batch, the same
     * philosophy {@code GitHubSyncService} applies per-repo on a connector sync.
     *
     * @return how many items were actually updated
     */
    @Transactional
    public int bulkUpdateState(List<UUID> ids, TriageState newState, UUID assigneeId, User actingUser) {
        int updated = 0;
        for (UUID id : ids) {
            if (updateState(id, newState, assigneeId, null, null, actingUser).isPresent()) {
                updated++;
            }
        }
        return updated;
    }

    /** One item's triage history, oldest first. Empty when {@code id} resolves to neither table. */
    @Transactional(readOnly = true)
    public Optional<List<TriageEventResponse>> history(UUID id) {
        Optional<Target> target = resolve(id);
        if (target.isEmpty()) {
            return Optional.empty();
        }
        Target t = target.get();
        List<TriageEvent> events = t.isAlert()
                ? eventRepository.findAllByVulnerabilityAlertIdOrderByCreatedAtAsc(id)
                : eventRepository.findAllByCompromiseFindingIdOrderByCreatedAtAsc(id);
        return Optional.of(events.stream().map(TriageService::toEventResponse).toList());
    }

    /* ------------------------------------------------------------------ */
    /* Resolution across the typed union                                  */
    /* ------------------------------------------------------------------ */

    private Optional<Target> resolve(UUID id) {
        Optional<VulnerabilityAlert> alert = alertRepository.findById(id);
        if (alert.isPresent()) {
            return Optional.of(new Target(alert.get(), null));
        }
        return findingRepository.findById(id).map(finding -> new Target(null, finding));
    }

    private TriageEvent appendEvent(Target t, TriageState fromState, TriageState toState, String comment, User actingUser) {
        TriageEvent event = new TriageEvent();
        t.attach(event);
        event.setFromState(fromState);
        event.setToState(toState);
        event.setComment(comment);
        event.setChangedBy(actingUser);
        return eventRepository.save(event);
    }

    private static TriageEventResponse toEventResponse(TriageEvent event) {
        User changedBy = event.getChangedBy();
        return new TriageEventResponse(
                event.getId(),
                event.getFromState(),
                event.getToState(),
                event.getComment(),
                changedBy == null ? null : changedBy.getId(),
                changedBy == null ? null : displayName(changedBy),
                event.getCreatedAt());
    }

    private static String displayName(User user) {
        return user.getDisplayName() != null ? user.getDisplayName() : user.getEmail();
    }

    /**
     * The resolved item — a {@code VulnerabilityAlert} or a {@code CompromiseFinding}, never both.
     * A private adapter, not a shared entity interface — see the class Javadoc for why. A non-static
     * inner class so {@link #save()} can reach the enclosing service's two repositories directly.
     */
    private final class Target {

        private final VulnerabilityAlert alert;
        private final CompromiseFinding finding;

        Target(VulnerabilityAlert alert, CompromiseFinding finding) {
            this.alert = alert;
            this.finding = finding;
        }

        boolean isAlert() {
            return alert != null;
        }

        UUID getId() {
            return isAlert() ? alert.getId() : finding.getId();
        }

        ActionableItemType itemType() {
            return isAlert() ? ActionableItemType.VULNERABILITY : ActionableItemType.COMPROMISE;
        }

        TriageState getTriageState() {
            return isAlert() ? alert.getTriageState() : finding.getTriageState();
        }

        void setTriageState(TriageState state) {
            if (isAlert()) {
                alert.setTriageState(state);
            } else {
                finding.setTriageState(state);
            }
        }

        User getAssignee() {
            return isAlert() ? alert.getAssignee() : finding.getAssignee();
        }

        void setAssignee(User user) {
            if (isAlert()) {
                alert.setAssignee(user);
            } else {
                finding.setAssignee(user);
            }
        }

        LocalDateTime getSnoozedUntil() {
            return isAlert() ? alert.getSnoozedUntil() : finding.getSnoozedUntil();
        }

        void setSnoozedUntil(LocalDateTime snoozedUntil) {
            if (isAlert()) {
                alert.setSnoozedUntil(snoozedUntil);
            } else {
                finding.setSnoozedUntil(snoozedUntil);
            }
        }

        void attach(TriageEvent event) {
            if (isAlert()) {
                event.setVulnerabilityAlert(alert);
            } else {
                event.setCompromiseFinding(finding);
            }
        }

        void save() {
            if (isAlert()) {
                alertRepository.save(alert);
            } else {
                findingRepository.save(finding);
            }
        }

        TriageStatusResponse toStatusResponse() {
            User assignee = getAssignee();
            return new TriageStatusResponse(
                    getId(),
                    itemType(),
                    getTriageState(),
                    assignee == null ? null : assignee.getId(),
                    assignee == null ? null : displayName(assignee),
                    getSnoozedUntil());
        }
    }

}
