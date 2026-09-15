package net.jdesive.secy.model.compliance;

import net.jdesive.secy.persistence.entity.Asset;
import net.jdesive.secy.persistence.entity.DockerComplianceReport;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * One row of {@code GET /compliance/reports}.
 *
 * @param actionableItems how many ACTIVE actionable alerts the audited asset currently has — the
 *                        same predicate {@code GET /actionable} applies, not a count of this report's
 *                        own vulnerability lines. The report's findings are reconciled onto the
 *                        asset, so "how bad is this thing" is an asset question.
 */
public record ComplianceReportSummaryResponse(
        String id,
        String benchmarkId,
        String title,
        String version,
        UUID assetId,
        String assetName,
        String status,
        int passedControls,
        int failedControls,
        int skippedControls,
        int totalControls,
        long actionableItems,
        LocalDateTime scannedAt,
        LocalDateTime createdAt) {

    public static ComplianceReportSummaryResponse of(DockerComplianceReport report, long actionableItems) {
        Asset asset = report.getAsset();
        return new ComplianceReportSummaryResponse(
                report.getId(),
                report.getReportId(),
                report.getTitle(),
                report.getVersion(),
                asset == null ? null : asset.getId(),
                asset == null ? null : asset.getName(),
                report.getStatus(),
                report.getPassedControls(),
                report.getFailedControls(),
                report.getSkippedControls(),
                report.getTotalControls(),
                actionableItems,
                report.getScannedAt(),
                report.getCreatedAt());
    }

}
