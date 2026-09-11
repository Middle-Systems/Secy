package net.jdesive.secy.service;

import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.correlation.CorrelationService;
import net.jdesive.secy.persistence.DockerComplianceReportRepository;
import net.jdesive.secy.persistence.DockerMisconfigurationAlertRepository;
import net.jdesive.secy.persistence.DockerVulnerabilityAlertRepository;
import net.jdesive.secy.persistence.entity.DockerComplianceReport;
import net.jdesive.secy.persistence.entity.DockerMisconfigurationAlert;
import net.jdesive.secy.persistence.entity.DockerVulnerabilityAlert;
import net.jdesive.secy.persistence.entity.SBOM;
import net.jdesive.secy.persistence.entity.Vulnerability;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Optional;

/**
 * Alert generation entry points.
 *
 * <p>The SBOM path is a one-line delegation to {@link CorrelationService}, which owns the OSV-primary
 * / CPE-fallback engine. This class keeps the entry point so {@code VulnerabilityScanner} and the
 * compliance path have one door, and so the Docker/CIS generator below — a different entity graph
 * entirely — stays where callers expect it.
 */
@Slf4j
@Service
public class AlertService {

    private final DockerVulnerabilityAlertRepository dockerVulnerabilityAlertRepository;
    private final DockerMisconfigurationAlertRepository dockerMisconfigurationAlertRepository;

    private final DockerComplianceReportRepository dockerComplianceReportRepository;

    private final CorrelationService correlationService;

    @Autowired
    public AlertService(DockerVulnerabilityAlertRepository dockerVulnerabilityAlertRepository,
                        DockerMisconfigurationAlertRepository dockerMisconfigurationAlertRepository,
                        DockerComplianceReportRepository dockerComplianceReportRepository,
                        CorrelationService correlationService) {
        this.dockerVulnerabilityAlertRepository = dockerVulnerabilityAlertRepository;
        this.dockerMisconfigurationAlertRepository = dockerMisconfigurationAlertRepository;
        this.dockerComplianceReportRepository = dockerComplianceReportRepository;
        this.correlationService = correlationService;
    }

    public void generateDockerComplianceAlerts(String reportId) {
        Optional<DockerComplianceReport> optional = this.dockerComplianceReportRepository.findById(reportId);

        if (optional.isEmpty()) {
            throw new RuntimeException("Docker Compliance Report with id " + reportId + " not found");
        }

        this.generateAlerts(optional.get());
    }

    /**
     * Docker/CIS alerts are a separate entity ({@link DockerVulnerabilityAlert}) with no join to
     * {@link Vulnerability}, so the actionable funnel does not reach them yet. Phase 5 folds the
     * compliance path into the same enrichment once the report vulnerabilities resolve to CVEs;
     * until then these rows stay outside {@code GET /actionable} by design.
     */
    public void generateAlerts(DockerComplianceReport report) {
        report.getVulnerabilities().forEach(vuln -> {
            DockerVulnerabilityAlert alert = new DockerVulnerabilityAlert();
            alert.setDismissed(false);
            alert.setCreatedDate(new Date());
            alert.setLastModifiedDate(new Date());
            alert.setVulnerability(vuln);
            this.dockerVulnerabilityAlertRepository.save(alert);
        });
        report.getMisconfigurations().forEach(misconfig -> {
            DockerMisconfigurationAlert alert = new DockerMisconfigurationAlert();
            alert.setDismissed(false);
            alert.setCreatedDate(new Date());
            alert.setLastModifiedDate(new Date());
            alert.setMisconfiguration(misconfig);
            this.dockerMisconfigurationAlertRepository.save(alert);
        });
    }

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
