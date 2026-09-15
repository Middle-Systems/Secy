package net.jdesive.secy.model.compliance;

import net.jdesive.secy.persistence.entity.ComplianceStatus;
import net.jdesive.secy.persistence.entity.DockerComplianceControl;
import net.jdesive.secy.persistence.entity.DockerComplianceReportMisconfig;
import net.jdesive.secy.persistence.entity.DockerMisconfigurationReference;

import java.util.List;

/**
 * One configuration check in the Compliance view's misconfiguration list.
 *
 * @param resolution the remediation text, verbatim from the benchmark. Never elided: a compliance
 *                   finding without "and here is what to do about it" is a complaint, not a finding.
 */
public record ComplianceMisconfigurationResponse(
        String id,
        String controlId,
        String controlName,
        String checkId,
        String avdId,
        String type,
        String title,
        String description,
        String message,
        String resolution,
        String severity,
        ComplianceStatus status,
        String target,
        String primaryUrl,
        List<String> references) {

    public static ComplianceMisconfigurationResponse of(DockerComplianceReportMisconfig misconfig) {
        DockerComplianceControl control = misconfig.getControl();
        return new ComplianceMisconfigurationResponse(
                misconfig.getId(),
                control == null ? null : control.getControlId(),
                control == null ? null : control.getName(),
                misconfig.getCheckId(),
                misconfig.getAvdId(),
                misconfig.getType(),
                misconfig.getTitle(),
                misconfig.getDescription(),
                misconfig.getMessage(),
                misconfig.getResolution(),
                misconfig.getSeverity(),
                misconfig.getStatus(),
                misconfig.getTarget(),
                misconfig.getPrimaryUrl(),
                misconfig.getReferences().stream()
                        .map(DockerMisconfigurationReference::getUrl)
                        .filter(url -> url != null && !url.isBlank())
                        .toList());
    }

}
