package net.jdesive.secy.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import net.jdesive.secy.job.JobService;
import net.jdesive.secy.persistence.entity.Job;
import net.jdesive.secy.persistence.entity.JobType;
import net.jdesive.secy.persistence.entity.KEV;
import net.jdesive.secy.service.KEVService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@Tag(name = "KEV", description = "CISA Known Exploited Vulnerabilities catalog")
@RestController
@RequestMapping("kev")
public class KEVController {

    private final KEVService kevService;

    private final JobService jobService;

    @Autowired
    public KEVController(KEVService kevService, JobService jobService) {
        this.kevService = kevService;
        this.jobService = jobService;
    }

    @Operation(summary = "List KEV entries, paged and optionally filtered by a search term")
    @GetMapping
    public Page<KEV> getKevEntries(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "15") int size,
            @RequestParam(required = false) String search) {
        return kevService.getPagedKev(page, size, search);
    }

    /**
     * Breaking change: this was a synchronous {@code GET} that blocked for the whole feed pull.
     * It is now a {@code POST} that returns immediately with a job to poll.
     */
    @Operation(
            summary = "Queue an ingestion of the latest KEV catalog from CISA",
            description = "Returns immediately with a QUEUED job; poll GET /jobs/{id} for progress. "
                    + "Only one KEV ingestion runs at a time — if one is already queued or running, "
                    + "that job is returned instead of a new one.")
    @ApiResponse(responseCode = "202", description = "Ingestion queued (or already in flight)")
    @PostMapping("ingest")
    public ResponseEntity<Job> ingest(Principal principal) {
        return ResponseEntity.accepted().body(this.jobService.enqueue(JobType.KEV, principal));
    }

}
