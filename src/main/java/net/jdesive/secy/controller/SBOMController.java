package net.jdesive.secy.controller;

import net.jdesive.secy.model.cyclonedx.CycloneDXFile;
import net.jdesive.secy.service.AlertService;
import net.jdesive.secy.service.SBOMService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("sbom")
public class SBOMController {

    private SBOMService sbomService;
    private AlertService alertService;

    @Autowired
    public SBOMController(SBOMService sbomService, AlertService alertService) {
        this.sbomService = sbomService;
        this.alertService = alertService;
    }

    @PostMapping("cyclonedx/ingest")
    public void ingestCycloneDX(@RequestBody CycloneDXFile cycloneDXFile) {
        this.sbomService.ingestCycloneDX(cycloneDXFile);
    }

    @GetMapping("scan/{sbomId}")
    public void scanSbomForVulnerabilities(@PathVariable String sbomId) {
        this.alertService.generateAlerts(this.sbomService.getSbomById(sbomId));
    }

}
