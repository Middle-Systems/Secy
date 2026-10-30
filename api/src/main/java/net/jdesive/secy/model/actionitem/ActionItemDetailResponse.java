package net.jdesive.secy.model.actionitem;

import net.jdesive.secy.model.finding.FindingResponse;
import net.jdesive.secy.model.finding.FindingRef;
import net.jdesive.secy.persistence.entity.FindingType;
import net.jdesive.secy.persistence.entity.RemediationStatus;
import net.jdesive.secy.persistence.entity.StatusDerivation;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** {@code GET /action-items/{id}} — {@link ActionItemResponse}'s fields plus {@link #description} and every linked {@link #findings finding}, each with its own derived status. */
public record ActionItemDetailResponse(
        UUID id,
        String title,
        String description,
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
        List<FindingResponse> findings,
        LocalDateTime createdAt,
        UUID createdById,
        LocalDateTime updatedAt,
        LocalDateTime resolvedAt) {
}
