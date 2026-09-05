package net.jdesive.secy.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import net.jdesive.secy.job.JobService;
import net.jdesive.secy.persistence.entity.Job;
import net.jdesive.secy.persistence.entity.JobStatus;
import net.jdesive.secy.persistence.entity.JobType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.UUID;

/**
 * Read side of the ingestion queue. {@code POST /{feed}/ingest} enqueues; the client polls here.
 */
@Tag(name = "Jobs", description = "Background feed-ingestion jobs")
@RestController
@RequestMapping("/jobs")
public class JobController {

    private static final int MAX_PAGE_SIZE = 100;

    private final JobService jobService;

    @Autowired
    public JobController(JobService jobService) {
        this.jobService = jobService;
    }

    @Operation(summary = "Fetch a single ingestion job by id — poll this after enqueuing an ingest")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "The job"),
            @ApiResponse(responseCode = "404", description = "No job with that id", content = {})
    })
    @GetMapping("{id}")
    public Job getJob(@PathVariable UUID id) {
        return jobService.get(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "No job with id " + id));
    }

    @Operation(summary = "List ingestion jobs, most recent first, optionally filtered by type and status")
    @GetMapping
    public Page<Job> listJobs(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "15") int size,
            @Parameter(description = "Restrict to one feed") @RequestParam(required = false) JobType type,
            @Parameter(description = "Restrict to one lifecycle state") @RequestParam(required = false) JobStatus status) {
        return jobService.list(Math.max(page, 0), Math.min(Math.max(size, 1), MAX_PAGE_SIZE), type, status);
    }

}
