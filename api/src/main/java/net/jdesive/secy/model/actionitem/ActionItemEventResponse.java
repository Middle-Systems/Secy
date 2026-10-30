package net.jdesive.secy.model.actionitem;

import net.jdesive.secy.persistence.entity.ActionItemEventType;
import net.jdesive.secy.persistence.entity.FindingType;
import net.jdesive.secy.persistence.entity.RemediationStatus;
import net.jdesive.secy.persistence.entity.StatusDerivation;

import java.time.LocalDateTime;
import java.util.UUID;

/** One row of {@code GET /action-items/{id}/history} — the M1j analogue of {@code TriageEventResponse}, broadened per {@link ActionItemEventType}. */
public record ActionItemEventResponse(
        UUID id,
        ActionItemEventType eventType,
        RemediationStatus fromStatus,
        RemediationStatus toStatus,
        StatusDerivation derivation,
        FindingType findingType,
        UUID findingId,
        UUID assigneeId,
        LocalDateTime riskAcceptedUntil,
        UUID riskApprovedById,
        UUID vexDocumentId,
        String comment,
        UUID changedById,
        String changedByName,
        LocalDateTime createdAt) {
}
