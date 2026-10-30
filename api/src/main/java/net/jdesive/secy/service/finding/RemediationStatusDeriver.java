package net.jdesive.secy.service.finding;

import net.jdesive.secy.model.finding.FindingRef;
import net.jdesive.secy.model.finding.FindingStatusBasis;
import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.FindingType;
import net.jdesive.secy.persistence.entity.RemediationStatus;
import net.jdesive.secy.persistence.entity.StatusDerivation;
import net.jdesive.secy.persistence.entity.TriageState;
import net.jdesive.secy.persistence.entity.VexStatus;

import java.time.LocalDateTime;
import java.util.List;

/**
 * The M1j status machine — a pure, static, no-Spring/no-JPA class, the same discipline
 * {@code RiskScorer}/{@code SbomQualityScorer} follow. Every rule takes {@code now} explicitly rather
 * than reading the clock itself, so tests can pin boundary conditions exactly (a snooze expiring at
 * exactly {@code now}, an acceptance expiring at exactly {@code now}).
 *
 * <p>See ROADMAP.md's "M1j — Finding &amp; Action-item model" §4 for the rules below in prose; this
 * class is their literal implementation, in the same rule order.
 */
public final class RemediationStatusDeriver {

    private RemediationStatusDeriver() {
    }

    /** {@link #forFinding}'s result: the derived status and which rule produced it. */
    public record FindingStatus(RemediationStatus status, FindingStatusBasis basis) {
    }

    /**
     * The stored fields of an {@code ActionItem} that {@link #forItem} needs — a snapshot, not the
     * entity itself, so this class stays JPA-free.
     */
    public record ActionItemSnapshot(RemediationStatus status, LocalDateTime resolvedAt, LocalDateTime riskAcceptedUntil) {
    }

    /** {@link #forItem}'s result — the effective status plus every derived flag {@code ActionItemResponse} surfaces. */
    public record ItemStatus(
            RemediationStatus status,
            StatusDerivation derivation,
            boolean reopened,
            List<FindingRef> reopenedFindings,
            boolean riskAcceptanceExpired,
            boolean awaitingVerification,
            boolean fixVerified) {
    }

    /**
     * A finding's derived status — §4b. First matching rule wins:
     * <ol>
     *   <li>{@code AUTO_RESOLVED} lifecycle → {@code RESOLVED}, basis {@code LIFECYCLE}</li>
     *   <li>vulnerability VEX {@code NOT_AFFECTED}/{@code FIXED} → {@code NOT_AFFECTED}/{@code RESOLVED}, basis {@code VEX}</li>
     *   <li>linked to an action item → that item's already-computed {@link ItemStatus#status()}, basis {@code ACTION_ITEM}</li>
     *   <li>vulnerability/compromise, by {@code TriageState} → basis {@code TRIAGE}</li>
     *   <li>otherwise {@code OPEN}, basis {@code DEFAULT}</li>
     * </ol>
     *
     * @param linkedItem the linked action item's already-derived {@link ItemStatus}, or null when
     *                    this finding is not linked to one
     */
    public static FindingStatus forFinding(ResolvedFinding f, ItemStatus linkedItem, LocalDateTime now) {
        if (f.lifecycleState() == AlertLifecycleState.AUTO_RESOLVED) {
            return new FindingStatus(RemediationStatus.RESOLVED, FindingStatusBasis.LIFECYCLE);
        }

        if (f.type() == FindingType.VULNERABILITY) {
            if (f.vexStatus() == VexStatus.NOT_AFFECTED) {
                return new FindingStatus(RemediationStatus.NOT_AFFECTED, FindingStatusBasis.VEX);
            }
            if (f.vexStatus() == VexStatus.FIXED) {
                return new FindingStatus(RemediationStatus.RESOLVED, FindingStatusBasis.VEX);
            }
        }

        if (linkedItem != null) {
            return new FindingStatus(linkedItem.status(), FindingStatusBasis.ACTION_ITEM);
        }

        if (f.type() == FindingType.VULNERABILITY || f.type() == FindingType.COMPROMISE) {
            TriageState triage = f.triageState();
            if (triage != null) {
                RemediationStatus status = switch (triage) {
                    case OPEN -> RemediationStatus.OPEN;
                    case ACKNOWLEDGED -> RemediationStatus.IN_PROGRESS;
                    case SNOOZED -> (f.snoozedUntil() != null && f.snoozedUntil().isAfter(now))
                            ? RemediationStatus.IN_PROGRESS : RemediationStatus.OPEN;
                    case RESOLVED -> RemediationStatus.RESOLVED;
                    case FALSE_POSITIVE -> RemediationStatus.NOT_AFFECTED;
                };
                return new FindingStatus(status, FindingStatusBasis.TRIAGE);
            }
        }

        return new FindingStatus(RemediationStatus.OPEN, FindingStatusBasis.DEFAULT);
    }

    /**
     * An action item's effective status — §4c. {@code linked} is every finding attached to the item
     * (any lifecycle state; this method does the {@code ACTIVE} filtering itself).
     */
    public static ItemStatus forItem(ActionItemSnapshot item, List<ResolvedFinding> linked, LocalDateTime now) {
        List<ResolvedFinding> activeExcludingVexFixed = linked.stream()
                .filter(f -> f.lifecycleState() == AlertLifecycleState.ACTIVE)
                .filter(f -> !isVulnWithVexStatus(f, VexStatus.FIXED))
                .toList();

        List<ResolvedFinding> remaining = activeExcludingVexFixed.stream()
                .filter(f -> !isVulnWithVexStatus(f, VexStatus.NOT_AFFECTED))
                .toList();

        List<ResolvedFinding> reappeared = remaining.stream()
                .filter(f -> f.lastSeenAt() != null && item.resolvedAt() != null
                        && f.lastSeenAt().isAfter(item.resolvedAt()))
                .toList();

        boolean fixVerified = !linked.isEmpty() && remaining.isEmpty();

        // Rule 1: resolved, but a linked finding reappeared since resolution.
        if (item.status() == RemediationStatus.RESOLVED && !reappeared.isEmpty()) {
            return new ItemStatus(RemediationStatus.OPEN, StatusDerivation.REOPENED_ON_REAPPEARANCE,
                    true, reappeared.stream().map(f -> new FindingRef(f.type(), f.id())).toList(),
                    false, false, fixVerified);
        }

        // Rule 2: resolved, nothing reappeared.
        if (item.status() == RemediationStatus.RESOLVED) {
            boolean awaitingVerification = !remaining.isEmpty();
            return new ItemStatus(RemediationStatus.RESOLVED, null, false, List.of(), false,
                    awaitingVerification, fixVerified);
        }

        // Rule 3: every linked active (non-VEX-FIXED) finding is a VEX NOT_AFFECTED vulnerability.
        boolean allVexNotAffected = !activeExcludingVexFixed.isEmpty()
                && activeExcludingVexFixed.stream().allMatch(f -> isVulnWithVexStatus(f, VexStatus.NOT_AFFECTED));
        if (allVexNotAffected) {
            return new ItemStatus(RemediationStatus.NOT_AFFECTED, StatusDerivation.VEX_NOT_AFFECTED,
                    false, List.of(), false, false, fixVerified);
        }

        // Rule 4: risk acceptance expired.
        if (item.status() == RemediationStatus.RISK_ACCEPTED
                && (item.riskAcceptedUntil() == null || !item.riskAcceptedUntil().isAfter(now))) {
            return new ItemStatus(RemediationStatus.OPEN, StatusDerivation.RISK_ACCEPTANCE_EXPIRED,
                    false, List.of(), true, false, fixVerified);
        }

        // Rule 5: the stored status stands.
        return new ItemStatus(item.status(), null, false, List.of(), false, false, fixVerified);
    }

    private static boolean isVulnWithVexStatus(ResolvedFinding f, VexStatus status) {
        return f.type() == FindingType.VULNERABILITY && f.vexStatus() == status;
    }

}
