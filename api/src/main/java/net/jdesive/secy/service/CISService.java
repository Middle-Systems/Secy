package net.jdesive.secy.service;

import net.jdesive.secy.model.docker.*;
import net.jdesive.secy.persistence.DockerComplianceReportRepository;
import net.jdesive.secy.persistence.entity.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class CISService {

    private DockerComplianceReportRepository dockerComplianceReportRepository;

    @Autowired
    public CISService(DockerComplianceReportRepository dockerComplianceReportRepository) {
        this.dockerComplianceReportRepository = dockerComplianceReportRepository;
    }

    public DockerComplianceReport ingestCISReport(CISReport report) {

        if (report.getResults() == null || report.getResults().isEmpty()) {
            return null;
        }

        DockerComplianceReport compReport = new DockerComplianceReport();
        compReport.setReportId(report.getId());
        compReport.setTitle(report.getTitle());
        compReport.setDescription(report.getDescription());
        compReport.setVersion(report.getVersion());

        if (report.getRelatedResources() != null || !report.getRelatedResources().isEmpty()) {
            for (String relatedResource : report.getRelatedResources()) {
                DockerComplianceReportReference reference = new DockerComplianceReportReference();
                reference.setUrl(relatedResource);
                reference.setReport(compReport);
                compReport.getReferences().add(reference);
            }
        }


        for (CISReportResult result : report.getResults()) {

            if (result.getResults() == null || result.getResults().isEmpty()) {
                continue;
            }

            for (CISReportResultResult finding : result.getResults()) {

                if (finding.getMisconfigurations() != null) {
                    for (CISReportMisconfig misconfiguration : finding.getMisconfigurations()) {
                        DockerComplianceReportMisconfig comMisconfig = new DockerComplianceReportMisconfig();
                        comMisconfig.setAvdId(misconfiguration.getAvdId());
                        comMisconfig.setTitle(misconfiguration.getTitle());
                        comMisconfig.setDescription(misconfiguration.getDescription());
                        comMisconfig.setMessage(misconfiguration.getMessage());
                        comMisconfig.setSeverity(misconfiguration.getSeverity());
                        comMisconfig.setType(misconfiguration.getType());
                        comMisconfig.setResolution(misconfiguration.getResolution());
                        comMisconfig.setPrimaryUrl(misconfiguration.getPrimaryUrl());
                        if (comMisconfig.getReferences() != null) {
                            for (DockerMisconfigurationReference dReference : comMisconfig.getReferences()) {
                                DockerMisconfigurationReference reference = new DockerMisconfigurationReference();
                                reference.setUrl(dReference.getUrl());
                                reference.setReport(comMisconfig);
                                comMisconfig.getReferences().add(reference);
                            }
                        }
                        comMisconfig.setReport(compReport);
                        compReport.getMisconfigurations().add(comMisconfig);
                    }
                }

                if (finding.getVulnerabilities() != null) {
                    for (CISReportVulnerability vulnerability : finding.getVulnerabilities()) {
                        DockerComplianceReportVulnerability comVuln = new DockerComplianceReportVulnerability();
                        comVuln.setId(vulnerability.getVulnerabilityId());
                        comVuln.setTitle(vulnerability.getTitle());
                        comVuln.setDescription(vulnerability.getDescription());
                        comVuln.setVersion(vulnerability.getInstalledVersion());
                        comVuln.setFixVersion(vulnerability.getFixedVersion());
                        comVuln.setAdvisoryUrl(vulnerability.getPrimaryUrl());
                        comVuln.setPackageName(vulnerability.getPkgName());
                        comVuln.setSeverity(vulnerability.getSeverity());
                        comVuln.setSeveritySource(vulnerability.getSeveritySource());
                        comVuln.setVulnStatus(vulnerability.getStatus());
                        comVuln.setVulnLastModifiedDate(vulnerability.getLastModifiedDate());
                        comVuln.setVulnPublishedDate(vulnerability.getPublishedDate());
                        comVuln.setReport(compReport);
                        compReport.getVulnerabilities().add(comVuln);
                    }
                }
            }
        }
        return this.dockerComplianceReportRepository.save(compReport);
    }
}
