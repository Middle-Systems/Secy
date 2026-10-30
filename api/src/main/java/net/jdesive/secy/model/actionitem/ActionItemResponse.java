package net.jdesive.secy.model.actionitem;

import net.jdesive.secy.model.finding.FindingRef;
import net.jdesive.secy.persistence.entity.FindingType;
import net.jdesive.secy.persistence.entity.RemediationStatus;
import net.jdesive.secy.persistence.entity.StatusDerivation;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * One row of {@code GET /action-items} — identity/scope, the effective-vs-stored status pair and
 * every derived flag {@code RemediationStatusDeriver.forItem} computes, people, per-type finding
 * counts, the computed {@link ActionItemScore}, the {@link RiskAcceptance} record (null unless
 * stored status is {@code RISK_ACCEPTED}), and timestamps.
 *
 * @param status              the EFFECTIVE status (what a client should show)
 * @param recordedStatus      the STORED status (what {@code PATCH} actually wrote)
 * @param derivation          why {@link #status} differs from {@link #recordedStatus}, or null
 * @param reopened            true when {@link #derivation} is {@code REOPENED_ON_REAPPEARANCE}
 * @param reopenedFindings    the findings that reopened it, when {@link #reopened} is true
 * @param riskAcceptanceExpired true when {@link #derivation} is {@code RISK_ACCEPTANCE_EXPIRED}
 * @param awaitingVerification stored {@code RESOLVED} but a linked finding is still active and hasn't reappeared
 * @param fixVerified         linked findings non-empty and none remain active (excluding VEX not-affected/fixed)
 */
public record ActionItemResponse(
        UUID id,
        String title,
        UUID productId,
        String productName,
        UUID assetId,
        String assetName,
        RemediationStatus status,
        RemediationStatus recordedStatus,
        StatusDerivation derivation,
        boolean reopened,
        List<FindingRef> reopenedFindings,
        boolean riskAcceptanceExpired,
        boolean awaitingVerification,
        boolean fixVerified,
        UUID assigneeId,
        String assigneeName,
        long findingCount,
        long remainingFindingCount,
        Map<FindingType, Long> findingCountsByType,
        ActionItemScore score,
        RiskAcceptance riskAcceptance,
        ActionItemFixSummary fixSummary,
        LocalDateTime createdAt,
        UUID createdById,
        LocalDateTime updatedAt,
        LocalDateTime resolvedAt) {
}
