package net.jdesive.secy.controller;

import net.jdesive.secy.persistence.entity.Vulnerability;
import net.jdesive.secy.service.NVDService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/nvd")
public class NVDController {

    private NVDService nvdService;

    @Autowired
    public NVDController(NVDService nvdService) {
        this.nvdService = nvdService;
    }

    @GetMapping("ingest")
    public void ingestNVDData() {
        this.nvdService.ingestData();
    }

    @GetMapping("id/{cveId}")
    public Vulnerability getVulnerabilityById(@PathVariable String cveId){
        return this.nvdService.getVulnerabilityById(cveId);
    }

    @GetMapping("search")
    public Page<Vulnerability> search(
            @RequestParam(defaultValue = "") String search,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        return nvdService.findByIdContainingIgnoreCaseOrDescriptionContainingIgnoreCase(search, page, size);
    }

}
