package net.jdesive.secy.service;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.persistence.*;
import net.jdesive.secy.persistence.entity.*;
import net.jdesive.secy.util.Version;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;

@Slf4j
@Service
public class AlertService {

    private final CPEMatchRepository cpeMatchRepository;
    private final VulnerabilityAlertRepository vulnerabilityAlertRepository;
    private final DockerVulnerabilityAlertRepository dockerVulnerabilityAlertRepository;
    private final DockerMisconfigurationAlertRepository dockerMisconfigurationAlertRepository;

    private final DockerComplianceReportRepository dockerComplianceReportRepository;

    @Autowired
    public AlertService(CPEMatchRepository cpeMatchRepository, VulnerabilityAlertRepository vulnerabilityAlertRepository,
                        DockerVulnerabilityAlertRepository dockerVulnerabilityAlertRepository,
                        DockerMisconfigurationAlertRepository dockerMisconfigurationAlertRepository,
                        DockerComplianceReportRepository dockerComplianceReportRepository) {
        this.cpeMatchRepository = cpeMatchRepository;
        this.vulnerabilityAlertRepository = vulnerabilityAlertRepository;
        this.dockerVulnerabilityAlertRepository = dockerVulnerabilityAlertRepository;
        this.dockerMisconfigurationAlertRepository = dockerMisconfigurationAlertRepository;
        this.dockerComplianceReportRepository = dockerComplianceReportRepository;
    }

    public void generateDockerComplianceAlerts(String reportId) {
        Optional<DockerComplianceReport> optional = this.dockerComplianceReportRepository.findById(reportId);

        if (optional.isEmpty()) {
            throw new RuntimeException("Docker Compliance Report with id " + reportId + " not found");
        }

        this.generateAlerts(optional.get());
    }

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
    
    public void generateAlerts(SBOM sbom) {
        log.info("Starting optimized vulnerability scan for SBOM: {}", sbom.getId());

        List<VulnerabilityAlert> newAlerts = new ArrayList<>();

        // 1. Group components by name to reduce redundant DB hits
        for (SBOMComponent component : sbom.getComponents()) {
            try {
                PackageURL purl = new PackageURL(component.getPurl());
                String name = purl.getName();
                String versionStr = purl.getVersion();

                // 2. Query only for CPEs that match this specific package name
                // You should add this method to your cpeMatchRepository
                String pattern = "cpe:2.3:a:%:" + name + ":%";
                List<CPEMatch> matches = cpeMatchRepository.findByCriteriaWithDetails(pattern);

                for (CPEMatch match : matches) {
                    // Criteria format: cpe:2.3:a:vendor:packageName:version:...
                    String[] splitStr = match.getCriteria().split(":");
                    if (splitStr.length < 6) continue;

                    String vulnVersion = splitStr[5];

                    if (isVulnerable(versionStr, vulnVersion)) {
                        VulnerabilityAlert alert = new VulnerabilityAlert();
                        alert.setVulnerability(match.getOperator().getCve());
                        alert.setComponent(component);
                        newAlerts.add(alert);
                    }
                }
            } catch (MalformedPackageURLException e) {
                log.error("Invalid PURL for component {}: {}", component.getId(), component.getPurl());
            }
        }

        // 3. Batch save everything at the end
        if (!newAlerts.isEmpty()) {
            vulnerabilityAlertRepository.saveAll(newAlerts);
            log.info("Scan complete. Generated {} alerts.", newAlerts.size());
        }
    }

    // Helper to keep the logic clean
    private boolean isVulnerable(String componentVersion, String cpeVersion) {
        if ("*".equals(cpeVersion) || "-".equals(cpeVersion)) return true;

        try {
            // Only attempt rich version comparison if both look like numbers/dots
            Version compV = new Version(componentVersion);
            Version vulnV = new Version(cpeVersion);
            return compV.compareTo(vulnV) <= 0;
        } catch (Exception e) {
            // Fallback: If we can't parse them, just do a direct match
            log.warn("Could not parse versions for comparison: {} vs {}", componentVersion, cpeVersion);
            return componentVersion.equals(cpeVersion);
        }
    }

}
