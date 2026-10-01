package net.jdesive.secy.model.finding;

import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.FindingType;
import net.jdesive.secy.persistence.entity.RemediationStatus;
import net.jdesive.secy.persistence.entity.TriageState;
import net.jdesive.secy.persistence.entity.VexJustification;
import net.jdesive.secy.persistence.entity.VexStatus;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * One row of {@code GET /findings} or {@code GET /findings/{type}/{id}} — a typed union DTO over the
 * five finding tables, per-type population per the M1j plan's field table. Fields a type doesn't have
 * are null: {@code severity} for the three newer types, risk score/VEX/triage fields for everything
 * but {@code VULNERABILITY} (VEX also excludes {@code COMPROMISE}, triage doesn't).
 */
public record FindingResponse(
        UUID id,
        FindingType type,
        String title,
        String summary,
        String severity,
        UUID productId,
        String productName,
        UUID assetId,
        String assetName,
        String componentName,
        String componentVersion,
        String componentPurl,
        AlertLifecycleState lifecycleState,
        LocalDateTime createdAt,
        LocalDateTime lastSeenAt,
        Double riskScore,
        VexStatus vexStatus,
        VexJustification vexJustification,
        boolean vexConflict,
        TriageState triageState,
        LocalDateTime snoozedUntil,
        RemediationStatus status,
        FindingStatusBasis statusBasis,
        UUID actionItemId,
        String detailPath,
        FindingFix fix) {
}
