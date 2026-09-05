package net.jdesive.secy.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import net.jdesive.secy.model.docker.CISReport;
import net.jdesive.secy.persistence.entity.DockerComplianceReport;
import net.jdesive.secy.service.AlertService;
import net.jdesive.secy.service.CISService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@Tag(name = "CIS", description = "CIS benchmark / docker compliance reports and the alerts derived from them")
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

    @Operation(summary = "Ingest a CIS docker compliance report")
    @PostMapping("/docker/ingest")
    public DockerComplianceReport ingestCISDocker(@RequestBody CISReport report) {
        return this.cisService.ingestCISReport(report);
    }

    @Operation(summary = "Generate misconfiguration and vulnerability alerts for an ingested report")
    @GetMapping("/docker/scan/{reportId}")
    public void scanCISDocker(@PathVariable String reportId) {
        this.alertService.generateDockerComplianceAlerts(reportId);
    }

}
