package net.jdesive.secy.model.compliance;

import net.jdesive.secy.persistence.entity.ComplianceStatus;
import net.jdesive.secy.persistence.entity.DockerComplianceControl;

/** One control in {@code GET /compliance/reports/{id}}'s breakdown. */
public record ComplianceControlResponse(
        String id,
        String controlId,
        String name,
        String severity,
        ComplianceStatus status,
        int failedChecks) {

    public static ComplianceControlResponse of(DockerComplianceControl control) {
        return new ComplianceControlResponse(
                control.getId(),
                control.getControlId(),
                control.getName(),
                control.getSeverity(),
                control.getStatus(),
                control.getFailedChecks());
    }

}
