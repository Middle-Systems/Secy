package net.jdesive.secy.model.compliance;

import net.jdesive.secy.persistence.entity.ComplianceStatus;

import java.util.List;

/**
 * One benchmark control and the checks that were run for it.
 *
 * @param status rolled up from {@link #checks} by {@link ComplianceStatus#rollUp}; a control with no
 *               checks reported is {@link ComplianceStatus#SKIP}, never a silent pass
 */
public record NormalizedControl(String controlId,
                                String name,
                                String description,
                                String severity,
                                ComplianceStatus status,
                                List<NormalizedMisconfiguration> checks) {

    public NormalizedControl {
        checks = checks == null ? List.of() : List.copyOf(checks);
    }

    /** How many of this control's checks failed. */
    public int failedChecks() {
        return (int) checks.stream().filter(check -> check.status() == ComplianceStatus.FAIL).count();
    }

}
