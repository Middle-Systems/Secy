package net.jdesive.secy.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.correlation.CorrelationService;
import net.jdesive.secy.persistence.entity.SBOM;
import org.springframework.stereotype.Service;

/**
 * Alert generation entry point for the SBOM path.
 *
 * <h2>What Phase 5 removed from here</h2>
 *
 * <p>This class used to carry a second generator, {@code generateAlerts(DockerComplianceReport)},
 * which wrote {@code DockerVulnerabilityAlert} and {@code DockerMisconfigurationAlert} rows. Neither
 * table joined {@code Vulnerability}, so neither could ever be enriched, ranked or surfaced — they
 * were written by one endpoint and read by nothing, for four phases.
 *
 * <p>Phase 5 routes a compliance report's vulnerability half through {@code ComplianceService} →
 * {@code AssetService.applyScan} → {@code CorrelationService}, i.e. the same funnel an SBOM or an
 * infrastructure scan takes, and its misconfiguration half stays a first-class compliance concept
 * read from {@code GET /compliance/reports/{id}}. Both dead alert entities and their repositories
 * are gone; migration {@code 010} drops their tables.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AlertService {

    private final CorrelationService correlationService;

    /**
     * Correlate an SBOM and reconcile its alerts.
     *
     * <p>Delegates to {@link CorrelationService#correlate(SBOM)}. Safe to call repeatedly on the same
     * SBOM: matches that still hold are updated in place, matches that no longer hold are
     * auto-resolved, and no {@code (component, CVE)} pair is ever duplicated.
     */
    public void generateAlerts(SBOM sbom) {
        correlationService.correlate(sbom);
    }

}
