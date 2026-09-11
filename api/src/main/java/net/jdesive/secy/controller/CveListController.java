package net.jdesive.secy.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import net.jdesive.secy.job.JobService;
import net.jdesive.secy.persistence.entity.Job;
import net.jdesive.secy.persistence.entity.JobType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@Tag(name = "CVE List", description = "CVE List v5.1 + CISA-ADP Vulnrichment bulk snapshot")
@RestController
@RequestMapping("cve-list")
public class CveListController {

    private final JobService jobService;

    @Autowired
    public CveListController(JobService jobService) {
        this.jobService = jobService;
    }

    @Operation(
            summary = "Queue a pull of the current CVE List v5 bulk snapshot",
            description = "Discovers the latest cvelistV5 GitHub release's zip asset and applies cveStatus, "
                    + "CVSS (NVD > CNA > ADP precedence), SSVC decision points and CWE onto existing "
                    + "vulnerabilities rows. Returns immediately with a QUEUED job; poll GET /jobs/{id} for "
                    + "progress. Only one CVE List ingestion runs at a time — if one is already queued or "
                    + "running, that job is returned instead of a new one.")
    @ApiResponse(responseCode = "202", description = "Ingestion queued (or already in flight)")
    @PostMapping("ingest")
    public ResponseEntity<Job> ingest(Principal principal) {
        return ResponseEntity.accepted().body(this.jobService.enqueue(JobType.CVE_LIST, principal));
    }

}
