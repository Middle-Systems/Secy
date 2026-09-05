package net.jdesive.secy.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import net.jdesive.secy.job.JobService;
import net.jdesive.secy.persistence.entity.Job;
import net.jdesive.secy.persistence.entity.JobType;
import net.jdesive.secy.persistence.entity.Vulnerability;
import net.jdesive.secy.service.NVDService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@Tag(name = "NVD", description = "CVE records ingested from the NIST National Vulnerability Database")
@RestController
@RequestMapping("/nvd")
public class NVDController {

    private NVDService nvdService;

    private final JobService jobService;

    @Autowired
    public NVDController(NVDService nvdService, JobService jobService) {
        this.nvdService = nvdService;
        this.jobService = jobService;
    }

    /**
     * Breaking change: this was a synchronous {@code GET} that blocked for the whole feed pull —
     * minutes, for NVD. It is now a {@code POST} that returns immediately with a job to poll.
     */
    @Operation(
            summary = "Queue an ingestion of CVE records from the NVD feed",
            description = "Returns immediately with a QUEUED job; poll GET /jobs/{id} for progress. "
                    + "Only one NVD ingestion runs at a time — if one is already queued or running, "
                    + "that job is returned instead of a new one.")
    @ApiResponse(responseCode = "202", description = "Ingestion queued (or already in flight)")
    @PostMapping("ingest")
    public ResponseEntity<Job> ingestNVDData(Principal principal) {
        return ResponseEntity.accepted().body(this.jobService.enqueue(JobType.NVD, principal));
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
