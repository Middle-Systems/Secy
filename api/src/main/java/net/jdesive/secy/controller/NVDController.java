package net.jdesive.secy.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import net.jdesive.secy.persistence.entity.Vulnerability;
import net.jdesive.secy.service.NVDService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.web.bind.annotation.*;

@Tag(name = "NVD", description = "CVE records ingested from the NIST National Vulnerability Database")
@RestController
@RequestMapping("/nvd")
public class NVDController {

    private NVDService nvdService;

    @Autowired
    public NVDController(NVDService nvdService) {
        this.nvdService = nvdService;
    }

    @Operation(summary = "Ingest CVE records from the NVD feed")
    @GetMapping("ingest")
    public void ingestNVDData() {
        this.nvdService.ingestData();
    }

    @Operation(summary = "Fetch a single vulnerability by its CVE id")
    @GetMapping("id/{cveId}")
    public Vulnerability getVulnerabilityById(@PathVariable String cveId){
        return this.nvdService.getVulnerabilityById(cveId);
    }

    @Operation(summary = "Search vulnerabilities by CVE id or description, paged")
    @GetMapping("search")
    public Page<Vulnerability> search(
            @RequestParam(defaultValue = "") String search,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        return nvdService.findByIdContainingIgnoreCaseOrDescriptionContainingIgnoreCase(search, page, size);
    }

}
