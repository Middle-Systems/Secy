package net.jdesive.secy.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import net.jdesive.secy.persistence.entity.EPSS;
import net.jdesive.secy.service.EPSSService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "EPSS", description = "FIRST Exploit Prediction Scoring System data")
@RestController
@RequestMapping("epss")
public class EPSSController {

    private EPSSService epssService;

    @Autowired
    public EPSSController(EPSSService epssService) {
        this.epssService = epssService;
    }

    @Operation(summary = "List EPSS scores, paged and optionally filtered by a search term")
    @GetMapping
    public Page<EPSS> getEpssEntries(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "15") int size,
            @RequestParam(required = false) String search) {
        return epssService.getPagedEpss(page, size, search);
    }

    @Operation(summary = "Ingest the latest EPSS scores from FIRST")
    @GetMapping("ingest")
    public void ingest() {
        this.epssService.ingestEPSSData();
    }

}
