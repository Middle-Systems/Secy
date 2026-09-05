package net.jdesive.secy.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import net.jdesive.secy.job.JobService;
import net.jdesive.secy.persistence.entity.EPSS;
import net.jdesive.secy.persistence.entity.Job;
import net.jdesive.secy.persistence.entity.JobType;
import net.jdesive.secy.service.EPSSService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@Tag(name = "EPSS", description = "FIRST Exploit Prediction Scoring System data")
@RestController
@RequestMapping("epss")
public class EPSSController {

    private EPSSService epssService;

    private final JobService jobService;

    @Autowired
    public EPSSController(EPSSService epssService, JobService jobService) {
        this.epssService = epssService;
        this.jobService = jobService;
    }

    @Operation(summary = "List EPSS scores, paged and optionally filtered by a search term")
    @GetMapping
    public Page<EPSS> getEpssEntries(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "15") int size,
            @RequestParam(required = false) String search) {
        return epssService.getPagedEpss(page, size, search);
    }

    /**
     * Breaking change: this was a synchronous {@code GET} that blocked for the whole feed pull.
     * It is now a {@code POST} that returns immediately with a job to poll.
     */
    @Operation(
            summary = "Queue an ingestion of the latest EPSS scores from FIRST",
            description = "Returns immediately with a QUEUED job; poll GET /jobs/{id} for progress. "
                    + "Only one EPSS ingestion runs at a time — if one is already queued or running, "
                    + "that job is returned instead of a new one.")
    @ApiResponse(responseCode = "202", description = "Ingestion queued (or already in flight)")
    @PostMapping("ingest")
    public ResponseEntity<Job> ingest(Principal principal) {
        return ResponseEntity.accepted().body(this.jobService.enqueue(JobType.EPSS, principal));
    }

}
