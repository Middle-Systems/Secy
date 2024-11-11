package net.jdesive.secy.controller;

import net.jdesive.secy.model.docker.CISReport;
import net.jdesive.secy.persistence.entity.DockerComplianceReport;
import net.jdesive.secy.service.AlertService;
import net.jdesive.secy.service.CISService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("cis")
public class CISController {

    private final CISService cisService;
    private final AlertService alertService;

    @Autowired
    public CISController(CISService cisService, AlertService alertService) {
        this.cisService = cisService;
        this.alertService = alertService;
    }

    @PostMapping("/docker/ingest")
    public DockerComplianceReport ingestCISDocker(@RequestBody CISReport report) {
        return this.cisService.ingestCISReport(report);
    }

    @GetMapping("/docker/scan/{reportId}")
    public void scanCISDocker(@PathVariable String reportId) {
        this.alertService.generateDockerComplianceAlerts(reportId);
    }

}
