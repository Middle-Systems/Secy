package net.jdesive.secy.service.finding;

import net.jdesive.secy.model.finding.FindingFix;
import net.jdesive.secy.persistence.entity.AlertLifecycleState;
import net.jdesive.secy.persistence.entity.FindingType;
import net.jdesive.secy.persistence.entity.TriageState;
import net.jdesive.secy.persistence.entity.VexJustification;
import net.jdesive.secy.persistence.entity.VexStatus;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * An immutable snapshot of one row of the {@code Finding} union, resolved by {@link FindingResolver}
 * — a plain record, not an entity interface, mirroring why {@code TriageService.Target} is a private
 * adapter rather than a shared JPA supertype (see that class's Javadoc).
 *
 * <p>Fields the finding's own type doesn't have are null/false: {@code severity} for the three newer
 * types (no severity concept — M1i's scope decision still holds), {@code riskScore}/VEX/triage fields
 * for everything but {@code VULNERABILITY} (VEX/triage also apply to {@code COMPROMISE}, minus
 * {@code riskScore} and VEX), {@code assetId}/{@code assetName} for the three plain-{@code productId}
 * types (no asset concept).
 */
public record ResolvedFinding(
        FindingType type,
        UUID id,
        UUID tenantId,
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
        FindingFix fix) {

    /** {@code /findings/{type}/{id}}'s sibling per-type detail path — see the M1j plan's table. */
    public String detailPath() {
        return switch (type) {
            case VULNERABILITY -> "/actionable/" + id;
            case COMPROMISE -> "/compromise/" + id;
            case LIFECYCLE_DRIFT -> "/lifecycle-drift/" + id;
            case QUANTUM_VULNERABLE -> "/cbom/quantum-findings/" + id;
            case SBOM_QUALITY -> "/sbom-quality/" + id;
            case PROVENANCE -> null;
        };
    }

}
