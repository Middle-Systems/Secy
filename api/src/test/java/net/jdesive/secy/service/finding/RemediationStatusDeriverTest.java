package net.jdesive.secy.service.finding;

import net.jdesive.secy.model.finding.FindingStatusBasis;
import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.FindingType;
import net.jdesive.secy.persistence.entity.RemediationStatus;
import net.jdesive.secy.persistence.entity.StatusDerivation;
import net.jdesive.secy.persistence.entity.TriageState;
import net.jdesive.secy.persistence.entity.VexStatus;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pure unit tests for {@link RemediationStatusDeriver} — no Spring context, {@code now} pinned and
 * passed explicitly to every call so boundary conditions (a snooze/acceptance expiring at exactly
 * {@code now}, a reopen at exactly {@code resolvedAt}) are deterministic.
 */
class RemediationStatusDeriverTest {

    private static final LocalDateTime NOW = LocalDateTime.of(2026, 1, 15, 12, 0, 0);

    /* ------------------------------------------------------------------ */
    /* Finding-level: precedence                                          */
    /* ------------------------------------------------------------------ */

    @Test
    void autoResolvedBeatsEverythingElse() {
        RemediationStatusDeriver.ItemStatus resolvedItem =
                new RemediationStatusDeriver.ItemStatus(RemediationStatus.RESOLVED, null, false, List.of(), false, false, false);
        ResolvedFinding f = finding(FindingType.VULNERABILITY, AlertLifecycleState.AUTO_RESOLVED,
                VexStatus.NOT_AFFECTED, TriageState.RESOLVED, null, null);

        RemediationStatusDeriver.FindingStatus result = RemediationStatusDeriver.forFinding(f, resolvedItem, NOW);

        assertThat(result.status()).isEqualTo(RemediationStatus.RESOLVED);
        assertThat(result.basis()).isEqualTo(FindingStatusBasis.LIFECYCLE);
    }

    @Test
    void vexBeatsLinkedItemAndTriage() {
        RemediationStatusDeriver.ItemStatus openItem =
                new RemediationStatusDeriver.ItemStatus(RemediationStatus.OPEN, null, false, List.of(), false, false, false);
        ResolvedFinding f = finding(FindingType.VULNERABILITY, AlertLifecycleState.ACTIVE,
                VexStatus.NOT_AFFECTED, TriageState.OPEN, null, null);

        RemediationStatusDeriver.FindingStatus result = RemediationStatusDeriver.forFinding(f, openItem, NOW);

        assertThat(result.status()).isEqualTo(RemediationStatus.NOT_AFFECTED);
        assertThat(result.basis()).isEqualTo(FindingStatusBasis.VEX);
    }

    @Test
    void linkedItemBeatsTriage() {
        RemediationStatusDeriver.ItemStatus inProgressItem =
                new RemediationStatusDeriver.ItemStatus(RemediationStatus.IN_PROGRESS, null, false, List.of(), false, false, false);
        ResolvedFinding f = finding(FindingType.VULNERABILITY, AlertLifecycleState.ACTIVE, null, TriageState.OPEN, null, null);

        RemediationStatusDeriver.FindingStatus result = RemediationStatusDeriver.forFinding(f, inProgressItem, NOW);

        assertThat(result.status()).isEqualTo(RemediationStatus.IN_PROGRESS);
        assertThat(result.basis()).isEqualTo(FindingStatusBasis.ACTION_ITEM);
    }

    @Test
    void unlinkedFallsThroughToTriage() {
        ResolvedFinding f = finding(FindingType.VULNERABILITY, AlertLifecycleState.ACTIVE, null, TriageState.ACKNOWLEDGED, null, null);

        RemediationStatusDeriver.FindingStatus result = RemediationStatusDeriver.forFinding(f, null, NOW);

        assertThat(result.status()).isEqualTo(RemediationStatus.IN_PROGRESS);
        assertThat(result.basis()).isEqualTo(FindingStatusBasis.TRIAGE);
    }

    @Test
    void unlinkedUntriagedNonVulnCompromiseTypeIsDefaultOpen() {
        ResolvedFinding f = finding(FindingType.LIFECYCLE_DRIFT, AlertLifecycleState.ACTIVE, null, null, null, null);

        RemediationStatusDeriver.FindingStatus result = RemediationStatusDeriver.forFinding(f, null, NOW);

        assertThat(result.status()).isEqualTo(RemediationStatus.OPEN);
        assertThat(result.basis()).isEqualTo(FindingStatusBasis.DEFAULT);
    }

    /* ------------------------------------------------------------------ */
    /* Finding-level: every TriageState mapping                           */
    /* ------------------------------------------------------------------ */

    @Test
    void triageOpenMapsToOpen() {
        assertTriageMapsTo(TriageState.OPEN, null, RemediationStatus.OPEN);
    }

    @Test
    void triageAcknowledgedMapsToInProgress() {
        assertTriageMapsTo(TriageState.ACKNOWLEDGED, null, RemediationStatus.IN_PROGRESS);
    }

    @Test
    void triageSnoozedNotYetExpiredMapsToInProgress() {
        assertTriageMapsTo(TriageState.SNOOZED, NOW.plusMinutes(1), RemediationStatus.IN_PROGRESS);
    }

    @Test
    void triageSnoozedExpiringExactlyNowMapsToOpen() {
        assertTriageMapsTo(TriageState.SNOOZED, NOW, RemediationStatus.OPEN);
    }

    @Test
    void triageSnoozedWithNullSnoozedUntilMapsToOpen() {
        assertTriageMapsTo(TriageState.SNOOZED, null, RemediationStatus.OPEN);
    }

    @Test
    void triageResolvedMapsToResolved() {
        assertTriageMapsTo(TriageState.RESOLVED, null, RemediationStatus.RESOLVED);
    }

    @Test
    void triageFalsePositiveMapsToNotAffected() {
        assertTriageMapsTo(TriageState.FALSE_POSITIVE, null, RemediationStatus.NOT_AFFECTED);
    }

    private void assertTriageMapsTo(TriageState triage, LocalDateTime snoozedUntil, RemediationStatus expected) {
        ResolvedFinding f = finding(FindingType.VULNERABILITY, AlertLifecycleState.ACTIVE, null, triage, snoozedUntil, null);
        RemediationStatusDeriver.FindingStatus result = RemediationStatusDeriver.forFinding(f, null, NOW);
        assertThat(result.status()).isEqualTo(expected);
        assertThat(result.basis()).isEqualTo(FindingStatusBasis.TRIAGE);
    }

    /* ------------------------------------------------------------------ */
    /* Finding-level: VEX FIXED and conflict fall-through                 */
    /* ------------------------------------------------------------------ */

    @Test
    void vexFixedMapsToResolved() {
        ResolvedFinding f = finding(FindingType.VULNERABILITY, AlertLifecycleState.ACTIVE, VexStatus.FIXED, TriageState.OPEN, null, null);
        RemediationStatusDeriver.FindingStatus result = RemediationStatusDeriver.forFinding(f, null, NOW);
        assertThat(result.status()).isEqualTo(RemediationStatus.RESOLVED);
        assertThat(result.basis()).isEqualTo(FindingStatusBasis.VEX);
    }

    @Test
    void vexConflictLeavesStatusNullAndFallsThroughToTriage() {
        // A VEX conflict clears vexStatus to null rather than setting NOT_AFFECTED/FIXED.
        ResolvedFinding f = finding(FindingType.VULNERABILITY, AlertLifecycleState.ACTIVE, null, TriageState.OPEN, null, null);
        RemediationStatusDeriver.FindingStatus result = RemediationStatusDeriver.forFinding(f, null, NOW);
        assertThat(result.status()).isEqualTo(RemediationStatus.OPEN);
        assertThat(result.basis()).isEqualTo(FindingStatusBasis.TRIAGE);
    }

    /* ------------------------------------------------------------------ */
    /* Item-level: reopen boundaries                                      */
    /* ------------------------------------------------------------------ */

    @Test
    void reopenBoundaryLastSeenAtEqualToResolvedAtDoesNotReopen() {
        LocalDateTime resolvedAt = NOW.minusDays(1);
        RemediationStatusDeriver.ActionItemSnapshot item =
                new RemediationStatusDeriver.ActionItemSnapshot(RemediationStatus.RESOLVED, resolvedAt, null);
        ResolvedFinding f = finding(FindingType.VULNERABILITY, AlertLifecycleState.ACTIVE, null, null, null, resolvedAt);

        RemediationStatusDeriver.ItemStatus result = RemediationStatusDeriver.forItem(item, List.of(f), NOW);

        assertThat(result.status()).isEqualTo(RemediationStatus.RESOLVED);
        assertThat(result.reopened()).isFalse();
    }

    @Test
    void reopenBoundaryOneMicrosecondAfterResolvedAtDoesReopen() {
        LocalDateTime resolvedAt = NOW.minusDays(1);
        RemediationStatusDeriver.ActionItemSnapshot item =
                new RemediationStatusDeriver.ActionItemSnapshot(RemediationStatus.RESOLVED, resolvedAt, null);
        ResolvedFinding f = finding(FindingType.VULNERABILITY, AlertLifecycleState.ACTIVE, null, null, null,
                resolvedAt.plusNanos(1000));

        RemediationStatusDeriver.ItemStatus result = RemediationStatusDeriver.forItem(item, List.of(f), NOW);

        assertThat(result.status()).isEqualTo(RemediationStatus.OPEN);
        assertThat(result.derivation()).isEqualTo(StatusDerivation.REOPENED_ON_REAPPEARANCE);
        assertThat(result.reopened()).isTrue();
        assertThat(result.reopenedFindings()).containsExactly(new net.jdesive.secy.model.finding.FindingRef(f.type(), f.id()));
    }

    @Test
    void nullLastSeenAtNeverReopens() {
        LocalDateTime resolvedAt = NOW.minusDays(1);
        RemediationStatusDeriver.ActionItemSnapshot item =
                new RemediationStatusDeriver.ActionItemSnapshot(RemediationStatus.RESOLVED, resolvedAt, null);
        ResolvedFinding f = finding(FindingType.VULNERABILITY, AlertLifecycleState.ACTIVE, null, null, null, null);

        RemediationStatusDeriver.ItemStatus result = RemediationStatusDeriver.forItem(item, List.of(f), NOW);

        assertThat(result.status()).isEqualTo(RemediationStatus.RESOLVED);
        assertThat(result.reopened()).isFalse();
        assertThat(result.awaitingVerification()).isTrue();
    }

    @Test
    void autoResolvedWithBumpedLastSeenAtDoesNotReopen() {
        // The SbomQualityFindingService quirk: lastSeenAt is bumped even on an AUTO_RESOLVED write.
        LocalDateTime resolvedAt = NOW.minusDays(1);
        RemediationStatusDeriver.ActionItemSnapshot item =
                new RemediationStatusDeriver.ActionItemSnapshot(RemediationStatus.RESOLVED, resolvedAt, null);
        ResolvedFinding f = finding(FindingType.SBOM_QUALITY, AlertLifecycleState.AUTO_RESOLVED, null, null, null, NOW);

        RemediationStatusDeriver.ItemStatus result = RemediationStatusDeriver.forItem(item, List.of(f), NOW);

        assertThat(result.status()).isEqualTo(RemediationStatus.RESOLVED);
        assertThat(result.reopened()).isFalse();
        assertThat(result.fixVerified()).isTrue();
    }

    @Test
    void reappearedVexNotAffectedAlertDoesNotReopen() {
        LocalDateTime resolvedAt = NOW.minusDays(1);
        RemediationStatusDeriver.ActionItemSnapshot item =
                new RemediationStatusDeriver.ActionItemSnapshot(RemediationStatus.RESOLVED, resolvedAt, null);
        ResolvedFinding f = finding(FindingType.VULNERABILITY, AlertLifecycleState.ACTIVE, VexStatus.NOT_AFFECTED,
                null, null, resolvedAt.plusDays(1));

        RemediationStatusDeriver.ItemStatus result = RemediationStatusDeriver.forItem(item, List.of(f), NOW);

        assertThat(result.status()).isEqualTo(RemediationStatus.RESOLVED);
        assertThat(result.reopened()).isFalse();
        assertThat(result.awaitingVerification()).isFalse();
    }

    /* ------------------------------------------------------------------ */
    /* Item-level: risk-acceptance expiry boundary                        */
    /* ------------------------------------------------------------------ */

    @Test
    void riskAcceptanceExpiringExactlyNowIsExpired() {
        RemediationStatusDeriver.ActionItemSnapshot item =
                new RemediationStatusDeriver.ActionItemSnapshot(RemediationStatus.RISK_ACCEPTED, null, NOW);

        RemediationStatusDeriver.ItemStatus result = RemediationStatusDeriver.forItem(item, List.of(), NOW);

        assertThat(result.status()).isEqualTo(RemediationStatus.OPEN);
        assertThat(result.derivation()).isEqualTo(StatusDerivation.RISK_ACCEPTANCE_EXPIRED);
        assertThat(result.riskAcceptanceExpired()).isTrue();
    }

    @Test
    void riskAcceptanceStillInFutureStaysRiskAccepted() {
        RemediationStatusDeriver.ActionItemSnapshot item =
                new RemediationStatusDeriver.ActionItemSnapshot(RemediationStatus.RISK_ACCEPTED, null, NOW.plusSeconds(1));

        RemediationStatusDeriver.ItemStatus result = RemediationStatusDeriver.forItem(item, List.of(), NOW);

        assertThat(result.status()).isEqualTo(RemediationStatus.RISK_ACCEPTED);
        assertThat(result.riskAcceptanceExpired()).isFalse();
    }

    /* ------------------------------------------------------------------ */
    /* Item-level: VEX_NOT_AFFECTED                                       */
    /* ------------------------------------------------------------------ */

    @Test
    void allVexNotAffectedMapsItemToNotAffected() {
        RemediationStatusDeriver.ActionItemSnapshot item =
                new RemediationStatusDeriver.ActionItemSnapshot(RemediationStatus.OPEN, null, null);
        ResolvedFinding f1 = finding(FindingType.VULNERABILITY, AlertLifecycleState.ACTIVE, VexStatus.NOT_AFFECTED, null, null, null);
        ResolvedFinding f2 = finding(FindingType.VULNERABILITY, AlertLifecycleState.ACTIVE, VexStatus.NOT_AFFECTED, null, null, null);

        RemediationStatusDeriver.ItemStatus result = RemediationStatusDeriver.forItem(item, List.of(f1, f2), NOW);

        assertThat(result.status()).isEqualTo(RemediationStatus.NOT_AFFECTED);
        assertThat(result.derivation()).isEqualTo(StatusDerivation.VEX_NOT_AFFECTED);
    }

    @Test
    void mixedVexNotAffectedKeepsStoredStatus() {
        RemediationStatusDeriver.ActionItemSnapshot item =
                new RemediationStatusDeriver.ActionItemSnapshot(RemediationStatus.IN_PROGRESS, null, null);
        ResolvedFinding f1 = finding(FindingType.VULNERABILITY, AlertLifecycleState.ACTIVE, VexStatus.NOT_AFFECTED, null, null, null);
        ResolvedFinding f2 = finding(FindingType.COMPROMISE, AlertLifecycleState.ACTIVE, null, null, null, null);

        RemediationStatusDeriver.ItemStatus result = RemediationStatusDeriver.forItem(item, List.of(f1, f2), NOW);

        assertThat(result.status()).isEqualTo(RemediationStatus.IN_PROGRESS);
        assertThat(result.derivation()).isNull();
    }

    @Test
    void vexNotAffectedAppliesOverRiskAcceptedEvenWhenExpired() {
        RemediationStatusDeriver.ActionItemSnapshot item =
                new RemediationStatusDeriver.ActionItemSnapshot(RemediationStatus.RISK_ACCEPTED, null, NOW.minusDays(1));
        ResolvedFinding f = finding(FindingType.VULNERABILITY, AlertLifecycleState.ACTIVE, VexStatus.NOT_AFFECTED, null, null, null);

        RemediationStatusDeriver.ItemStatus result = RemediationStatusDeriver.forItem(item, List.of(f), NOW);

        assertThat(result.status()).isEqualTo(RemediationStatus.NOT_AFFECTED);
        assertThat(result.derivation()).isEqualTo(StatusDerivation.VEX_NOT_AFFECTED);
    }

    @Test
    void vexNotAffectedDoesNotApplyOverResolved() {
        LocalDateTime resolvedAt = NOW.minusDays(1);
        RemediationStatusDeriver.ActionItemSnapshot item =
                new RemediationStatusDeriver.ActionItemSnapshot(RemediationStatus.RESOLVED, resolvedAt, null);
        ResolvedFinding f = finding(FindingType.VULNERABILITY, AlertLifecycleState.ACTIVE, VexStatus.NOT_AFFECTED, null, null, null);

        RemediationStatusDeriver.ItemStatus result = RemediationStatusDeriver.forItem(item, List.of(f), NOW);

        assertThat(result.status()).isEqualTo(RemediationStatus.RESOLVED);
        assertThat(result.derivation()).isNull();
    }

    /* ------------------------------------------------------------------ */
    /* Item-level: empty/all-resolved linked sets                         */
    /* ------------------------------------------------------------------ */

    @Test
    void emptyLinkedListKeepsStoredStatusAndFixVerifiedFalse() {
        RemediationStatusDeriver.ActionItemSnapshot item =
                new RemediationStatusDeriver.ActionItemSnapshot(RemediationStatus.OPEN, null, null);

        RemediationStatusDeriver.ItemStatus result = RemediationStatusDeriver.forItem(item, List.of(), NOW);

        assertThat(result.status()).isEqualTo(RemediationStatus.OPEN);
        assertThat(result.fixVerified()).isFalse();
    }

    @Test
    void allAutoResolvedMakesFixVerifiedTrue() {
        RemediationStatusDeriver.ActionItemSnapshot item =
                new RemediationStatusDeriver.ActionItemSnapshot(RemediationStatus.OPEN, null, null);
        ResolvedFinding f1 = finding(FindingType.VULNERABILITY, AlertLifecycleState.AUTO_RESOLVED, null, null, null, null);
        ResolvedFinding f2 = finding(FindingType.LIFECYCLE_DRIFT, AlertLifecycleState.AUTO_RESOLVED, null, null, null, null);

        RemediationStatusDeriver.ItemStatus result = RemediationStatusDeriver.forItem(item, List.of(f1, f2), NOW);

        assertThat(result.status()).isEqualTo(RemediationStatus.OPEN);
        assertThat(result.fixVerified()).isTrue();
    }

    @Test
    void resolvedWithRemainingFindingsAndNoReappearanceIsAwaitingVerification() {
        LocalDateTime resolvedAt = NOW.minusDays(1);
        RemediationStatusDeriver.ActionItemSnapshot item =
                new RemediationStatusDeriver.ActionItemSnapshot(RemediationStatus.RESOLVED, resolvedAt, null);
        ResolvedFinding f = finding(FindingType.VULNERABILITY, AlertLifecycleState.ACTIVE, null, null, null, null);

        RemediationStatusDeriver.ItemStatus result = RemediationStatusDeriver.forItem(item, List.of(f), NOW);

        assertThat(result.status()).isEqualTo(RemediationStatus.RESOLVED);
        assertThat(result.reopened()).isFalse();
        assertThat(result.awaitingVerification()).isTrue();
    }

    /* ------------------------------------------------------------------ */
    /* Helper                                                             */
    /* ------------------------------------------------------------------ */

    private static ResolvedFinding finding(FindingType type, AlertLifecycleState lifecycleState, VexStatus vexStatus,
                                            TriageState triageState, LocalDateTime snoozedUntil, LocalDateTime lastSeenAt) {
        return new ResolvedFinding(
                type,
                UUID.randomUUID(),
                UUID.randomUUID(),
                "title", "summary", "severity",
                null, null, null, null,
                "component", "1.0.0", "pkg:test/component@1.0.0",
                lifecycleState,
                NOW.minusDays(30),
                lastSeenAt,
                null,
                vexStatus,
                null,
                false,
                triageState,
                snoozedUntil,
                null);
    }

}
