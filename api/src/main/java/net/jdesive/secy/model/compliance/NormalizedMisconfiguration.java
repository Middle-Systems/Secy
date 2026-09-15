package net.jdesive.secy.model.compliance;

import net.jdesive.secy.persistence.entity.ComplianceStatus;

import java.util.List;

/**
 * One configuration check inside a {@link NormalizedControl}.
 *
 * @param checkId    Trivy's own check id, e.g. {@code DS002}
 * @param avdId      the Aqua Vulnerability Database id, e.g. {@code AVD-DS-0002}
 * @param resolution the remediation text; the reason this screen is worth building
 * @param target     which scanned target the check ran against
 */
public record NormalizedMisconfiguration(String type,
                                         String checkId,
                                         String avdId,
                                         String title,
                                         String description,
                                         String message,
                                         String resolution,
                                         String severity,
                                         String primaryUrl,
                                         ComplianceStatus status,
                                         String target,
                                         List<String> references) {

    public NormalizedMisconfiguration {
        references = references == null ? List.of() : List.copyOf(references);
    }

}
