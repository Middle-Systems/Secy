package net.jdesive.secy.service;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import lombok.extern.slf4j.Slf4j;
import net.jdesive.secy.persistence.*;
import net.jdesive.secy.persistence.entity.*;
import net.jdesive.secy.util.Version;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Date;
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
        cpeMatchRepository.findAll().forEach(cpeMatch -> {
            String[] splitStr = cpeMatch.getCriteria().split(":");

            String packageName = splitStr[4];
            String packageVersion = splitStr[5];

            for (SBOMComponent component : sbom.getComponents()) {

                try {
                    PackageURL purl = new PackageURL(component.getPurl());
                    if (purl.getName().equals(packageName)) {
                        if (packageVersion.equals("*")) {
                            VulnerabilityAlert alert = new VulnerabilityAlert();
                            alert.setVulnerability(cpeMatch.getOperator().getCve());
                            alert.setComponent(component);
                            this.vulnerabilityAlertRepository.save(alert);
                            continue;
                        }
                        try {
                            Version packageVersionObj = new Version(purl.getVersion());
                            Version vulnVersion = new Version(packageVersion);
                            if(packageVersionObj.compareTo(vulnVersion) <= 0) {
                                VulnerabilityAlert alert = new VulnerabilityAlert();
                                alert.setVulnerability(cpeMatch.getOperator().getCve());
                                alert.setComponent(component);
                                this.vulnerabilityAlertRepository.save(alert);
                            }
                        } catch (IllegalArgumentException ex) {
                            log.error("Error parsing version for CPE: {}", cpeMatch);
                        }

                    }
                } catch (MalformedPackageURLException e) {
                    log.error("Error parsing package url of component {}", component.getId());
                }

            }
        });
    }

}
