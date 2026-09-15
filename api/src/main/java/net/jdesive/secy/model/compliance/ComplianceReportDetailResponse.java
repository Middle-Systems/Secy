package net.jdesive.secy.model.compliance;

import net.jdesive.secy.model.actionable.ActionableItemResponse;
import net.jdesive.secy.persistence.entity.Asset;
import net.jdesive.secy.persistence.entity.DockerComplianceReport;
import net.jdesive.secy.persistence.entity.DockerComplianceReportReference;
import org.springframework.data.domain.Page;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

/**
 * {@code GET /compliance/reports/{id}} — the audit, both halves.
 *
 * <p>The two halves are deliberately different shapes, because they are different things:
 *
 * <ul>
 *   <li>{@link #controls} + {@link #misconfigurations} are the benchmark result — pass/fail/skip
 *       counts, the per-control breakdown, and the paged list of checks with their remediation text.
 *       This is compliance, and it lives only here.</li>
 *   <li>{@link #actionableItems} is a plain page of {@link ActionableItemResponse} for the audited
 *       asset: the same rows, the same funnel and the same sort {@code GET /actionable} returns,
 *       obtained through the ordinary {@code assetId} filter. The report's vulnerability findings are
 *       not a separate kind of finding, so they are not given a separate shape.</li>
 * </ul>
 */
public record ComplianceReportDetailResponse(
        String id,
        String benchmarkId,
        String title,
        String description,
        String version,
        UUID assetId,
        String assetName,
        String status,
        int passedControls,
        int failedControls,
        int skippedControls,
        int totalControls,
        LocalDateTime scannedAt,
        LocalDateTime createdAt,
        List<String> relatedResources,
        List<ComplianceControlResponse> controls,
        Page<ComplianceMisconfigurationResponse> misconfigurations,
        Page<ActionableItemResponse> actionableItems) {

    public static ComplianceReportDetailResponse of(DockerComplianceReport report,
                                                    List<ComplianceControlResponse> controls,
                                                    Page<ComplianceMisconfigurationResponse> misconfigurations,
                                                    Page<ActionableItemResponse> actionableItems) {
        Asset asset = report.getAsset();
        return new ComplianceReportDetailResponse(
                report.getId(),
                report.getReportId(),
                report.getTitle(),
                report.getDescription(),
                report.getVersion(),
                asset == null ? null : asset.getId(),
                asset == null ? null : asset.getName(),
                report.getStatus(),
                report.getPassedControls(),
                report.getFailedControls(),
                report.getSkippedControls(),
                report.getTotalControls(),
                report.getScannedAt(),
                report.getCreatedAt(),
                report.getReferences().stream()
                        .map(DockerComplianceReportReference::getUrl)
                        .filter(url -> url != null && !url.isBlank())
                        .toList(),
                controls,
                misconfigurations,
                actionableItems);
    }

}
