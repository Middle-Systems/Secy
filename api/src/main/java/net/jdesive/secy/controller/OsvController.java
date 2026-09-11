package net.jdesive.secy.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import net.jdesive.secy.job.JobService;
import net.jdesive.secy.persistence.entity.Job;
import net.jdesive.secy.persistence.entity.JobType;
import net.jdesive.secy.persistence.entity.OsvAdvisory;
import net.jdesive.secy.service.OsvIngestService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@Tag(name = "OSV", description = "OSV per-ecosystem advisory mirror")
@RestController
@RequestMapping("osv")
public class OsvController {

    private final OsvIngestService osvIngestService;

    private final JobService jobService;

    @Autowired
    public OsvController(OsvIngestService osvIngestService, JobService jobService) {
        this.osvIngestService = osvIngestService;
        this.jobService = jobService;
    }

    @Operation(summary = "Browse the OSV mirror, optionally filtered by ecosystem and/or package name")
    @GetMapping
    public Page<OsvAdvisory> getAdvisories(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "15") int size,
            @RequestParam(required = false) String ecosystem,
            @RequestParam(required = false) String packageName) {
        return osvIngestService.getPaged(ecosystem, packageName, page, size);
    }

    @Operation(
            summary = "Queue a mirror of every configured OSV ecosystem export",
            description = "Returns immediately with a QUEUED job; poll GET /jobs/{id} for progress. "
                    + "Only one OSV ingestion runs at a time — if one is already queued or running, "
                    + "that job is returned instead of a new one.")
    @ApiResponse(responseCode = "202", description = "Ingestion queued (or already in flight)")
    @PostMapping("ingest")
    public ResponseEntity<Job> ingest(Principal principal) {
        return ResponseEntity.accepted().body(this.jobService.enqueue(JobType.OSV, principal));
    }

}
